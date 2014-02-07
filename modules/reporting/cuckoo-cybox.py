#!/usr/bin/env python2.7

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

try:
    from cybox.common import Hash, String, Time, ToolInformation, ToolInformationList
    from cybox.core import Observable, Observables, Object, RelatedObject, Relationship
    from cybox.objects.http_session_object import HTTPSession, HTTPMessage, HTTPRequestHeaderFields, HostField, HTTPClientRequest, HTTPRequestHeader, HTTPRequestResponse, HTTPRequestLine
    from cybox.objects.file_object import File
    from cybox.objects.win_executable_file_object import WinExecutableFile, PEImportList, PEImport, PEImportedFunctions, PEImportedFunction, PESectionList, PESection, Entropy, PESectionHeaderStruct, PEResourceList, PEVersionInfoResource, PEExports, PEExportedFunctions, PEExportedFunction
    from cybox.objects.dns_query_object import DNSQuery, DNSQuestion, DNSResourceRecords
    from cybox.objects.dns_record_object import DNSRecord
    from cybox.objects.uri_object import URI
    from cybox.objects.port_object import Port
    from cybox.objects.address_object import Address
    import cybox.utils
    import stix.utils

    from stix.core import STIXPackage, STIXHeader
    from stix.common import InformationSource
    from stix.common.handling import Handling
    from stix.bindings.data_marking import MarkingSpecificationType, MarkingStructureType, MarkingType
    from stix.bindings.extensions.marking.tlp import TLPMarkingStructureType
    HAVE_STIX = True
except ImportError:
    HAVE_STIX = False

import argparse
import os
import logging
import json
import sys
import datetime
import pytz
import urlparse
import ConfigParser
import psycopg2
import psycopg2.extras
import re

from dateutil import parser as dateparser
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO

__author__ = 'jan goebel <jan.goebel@siemens.com>'
__version__ = '0.0.2'

log = logging.getLogger(__name__)

class IPRange:
    def __init__(self, net):
        self.net = net
        (self.ip, self.pattern) = net.split("/")
        self.ip = self.dottedQuadToNum(self.ip)
        if self.pattern == "" or self.pattern == "0":
            self.pattern = ~0
        else:
            self.pattern = ~int("1" * (32 - int(self.pattern)), 2)

    def contains(self, tip):
        return self.ip & self.pattern == self.dottedQuadToNum(tip) & self.pattern

    def dottedQuadToNum(self,ip):
        l = map(int, ip.split('.'))
        addr = 0
        for byte in l:
            addr = 256*addr+byte
        return long(addr)

class HTTPRequestParser(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

class STIXReport(Report):

    def __create_cybox_pe_imports(self, imports):
        import_list = PEImportList()
        for imp in  imports:
            import_obj = PEImport()
            import_obj.file_name = String(imp['dll'])
            if len(imp['imports'])>0:
                imported_functions_object = PEImportedFunctions()
                for imp_funct in imp['imports']:
                    imported_function_object = PEImportedFunction()
                    imported_function_object.function_name = String(imp_funct['name'])
                    imported_function_object.virtual_address = imp_funct['address']
                    imported_functions_object.append(imported_function_object)
                import_obj.imported_functions = imported_functions_object
            import_list.append(import_obj)
        return import_list

    def __create_cybox_exported_functions(self, exports):
        export_list = PEExportedFunctions()
        for item in exports:
            exp = PEExportedFunction()
            exp.function_name = String(item['name'])
            exp.ordinal = item['ordinal']
            exp.entry_point = item['address']
            export_list.append(exp)
        return export_list

    def __create_cybox_pe_exports(self, exports):
        export_obj = PEExports()
        export_obj.number_of_functions = len(exports)
        export_obj.exported_functions = self.__create_cybox_exported_functions(exports)
        return export_obj

    def __create_cybox_pe_sections(self, sections):
        section_list = PESectionList()
        for section in sections:
            section_obj = PESection()

            entropy_obj = Entropy()
            entropy_obj.value = section['entropy']
            section_obj.entropy = entropy_obj

            section_header = PESectionHeaderStruct()
            section_header.name = section['name']
            section_header.virtual_address = section['virtual_address']
            section_header.virtual_size = section['virtual_size']
            section_header.size_of_raw_data = section['size_of_data']
            section_obj.section_header = section_header

            section_list.append(section_obj)
        return section_list

    def __create_cybox_pe_resources(self, vinf):
        pe_resources = PEResourceList()
        pe_versioninfo = PEVersionInfoResource()

        for item in vinf:
            if item['name'] == 'Comments':
                pe_versioninfo.comments = item['value']
            elif item['name'] == 'CompanyName':
                pe_versioninfo.companyname = item['value']
            elif item['name'] == 'FileDescription':
                pe_versioninfo.filedescription = item['value']
            elif item['name'] == 'FileVersion':
                pe_versioninfo.fileversion = item['value']
            elif item['name'] == 'InternalName':
                pe_versioninfo.internalname = item['value']
            elif item['name'] == 'LangID':
                pe_versioninfo.langid = item['value']
            elif item['name'] == 'LegalCopyright':
                pe_versioninfo.legalcopyright = item['value']
            elif item['name'] == 'LegalTrademarks':
                pe_versioninfo.legaltrademarks = item['value']
            elif item['name'] == 'OriginalFilename':
                pe_versioninfo.originalfilename = item['value']
            elif item['name'] == 'PrivateBuild':
                pe_versioninfo.privatebuild = item['value']
            elif item['name'] == 'ProductName':
                pe_versioninfo.productname = item['value']
            elif item['name'] == 'ProductVersion':
                pe_versioninfo.productversion = item['value']
            elif item['name'] == 'SpecialBuild':
                pe_versioninfo.specialbuild = item['value']

        pe_resources.append(pe_versioninfo)
        return pe_resources

    def __create_cybox_win_executable(self, fdict, sdict):
        wf = WinExecutableFile()
        if 'pe_imports' in sdict and len(sdict['pe_imports'])>0:
            imports_object = self.__create_cybox_pe_imports(sdict['pe_imports'])
            wf.imports = imports_object
        if 'pe_sections' in sdict and len(sdict['pe_sections'])>0:
            sections_object = self.__create_cybox_pe_sections(sdict['pe_sections'])
            wf.sections = sections_object
        if 'pe_versioninfo' in sdict and len(sdict['pe_versioninfo'])>0:
            resources_object = self.__create_cybox_pe_resources(sdict['pe_versioninfo'])
            wf.resources = resources_object
        if 'pe_exports' in sdict and len(sdict['pe_exports'])>0:
            exports_object = self.__create_cybox_pe_exports(sdict['pe_exports'])
            wf.exports = exports_object
        return wf

    def __create_cybox_main_file(self, fdict):
        f = File()
        f.file_name = String(fdict['name'])
        f.file_extension = String('.'+fdict['name'].rsplit('.')[-1])
        f.size_in_bytes = int(fdict['size'])
        f.add_hash(Hash(fdict['md5'], type_="MD5", exact=True))
        f.add_hash(Hash(fdict['sha1'], type_="SHA1", exact=True))
        f.add_hash(Hash(fdict['sha256'], type_="SHA256", exact=True))
        return f

    def __create_cybox_dropped_files(self, dropps, main_sha256):
        dropped = []
        if not dropps:
            return dropped
        for item in dropps:
            """ skip original file """
            if item['sha256'] == main_sha256:
                continue
            f = File()
            f.file_name = String(item['name'])
            f.file_extension = String('.'+item['name'].rsplit('.')[-1])
            f.size_in_bytes = int(item['size'])
            f.add_hash(Hash(item['md5'], type_="MD5", exact=True))
            f.add_hash(Hash(item['sha1'], type_="SHA1", exact=True))
            f.add_hash(Hash(item['sha256'], type_="SHA256", exact=True))
            dropped.append(f)
        return dropped

    def __create_cybox_domain_object(self, domain, whitelist):
        if not domain:
            return None
        for topleveldomain in whitelist['topleveldomain_whitelist']:
            if domain.endswith(topleveldomain):
                return None
        if domain in whitelist['specific_whitelist']:
            return None
        return URI(domain)

    def __create_cybox_ip_address_object(self, ip, whitelist):
        if not ip:
            return None
        for network in whitelist['network_whitelist']:
            if network.contains(ip):
                return None
        if ip in whitelist['specific_whitelist']:
            return None
        return Address(ip, Address.CAT_IPV4)

    def __create_cybox_port_object(self, port):
        if not port:
            return None
        pobj = Port()
        pobj.port_value = int(port)
        return pobj

    def __create_cybox_host_object(self, domain, port, whitelist):
        if not domain:
            return None
        if not port:
            port = 80
        hobj = HostField()
        hobj.domain_name = self.__create_cybox_domain_object(domain, whitelist)
        if not hobj.domain_name:
            return None
        hobj.port = self.__create_cybox_port_object(port)
        return hobj

    def __create_cybox_http_header(self, raw, port, whitelist):
        if not raw:
            return None
        request = HTTPRequestParser(raw)
        raw_header = str(request.headers)
        client_header = HTTPRequestHeaderFields()
        if 'accept' in request.headers:
            client_header.accept = String(request.headers['accept'])
        if 'content-length' in request.headers:
            client_header.content_length = int(request.headers['content-length'])
        if 'cache-control' in request.headers:
            client_header.cache_control = String(request.headers['cache-control'])
        if 'user-agent' in request.headers:
            client_header.user_agent = String(request.headers['user-agent'])
        if 'host' in request.headers:
            client_header.host = self.__create_cybox_host_object(request.headers['host'], port, whitelist)
            if not client_header.host:
                return None
        if 'pragma' in request.headers:
            client_header.pragma = String(request.headers['pragma'])
        if 'connection' in request.headers:
            client_header.connection = String(request.headers['connection'])

        http_req_head = HTTPRequestHeader()
        http_req_head.raw_header = String(raw_header)
        http_req_head.parsed_header = client_header
        return http_req_head

    def __create_cybox_http_message(self, msg):
        if not msg:
            return None
        _illegal_xml_chars_RE = re.compile(u"[\x00-\x08\x0b\x0c\x0e-\x1F\uD800-\uDFFF\uFFFE\uFFFF\n]")
        http_mess = HTTPMessage()
        http_mess.length = int(len(msg))
        http_mess.message_body = String(_illegal_xml_chars_RE.sub("?", msg))
        return http_mess

    def __create_cybox_http_req_line(self, method, value, version=None):
        if not method and not value:
            log.debug("no http method and no value ...")
            return None
        if not version:
            version = "1.0"
        req_line = HTTPRequestLine()
        req_line.version = String(version)
        if method:
            req_line.http_method = String(method)
        if value:
            if value.startswith('http'):
                vdict = urlparse.urlparse(value)
                value = vdict.path
            req_line.value = String(value)
        return req_line

    def __create_cybox_http_client_request(self, data, port, body, method, value, version, whitelist):
        if not port:
            port = 80
        http_client_req = HTTPClientRequest()
        if data:
            http_client_req.http_request_header = self.__create_cybox_http_header(data, port, whitelist)
            if not http_client_req.http_request_header:
                log.debug("no http request header object created ...")
                return None
        else:
            log.debug("no data information ...")
        if body:
            http_client_req.http_message_body = self.__create_cybox_http_message(body)
        else:
            log.debug("no body information ...")
        http_client_req.http_request_line = self.__create_cybox_http_req_line(method, value, version)
        return http_client_req

    def __create_cybox_http_request_response(self, entry, whitelist):
        if not entry:
            return None
        http_request_response = HTTPRequestResponse()
        http_request_response.http_client_request = self.__create_cybox_http_client_request(entry['data'], entry['port'], entry['body'], entry['method'], entry['path'], entry['version'], whitelist)
        if not http_request_response.http_client_request:
            log.debug("no client response object created ...")
            return None
        http_request_response.http_server_response = None
        return [http_request_response]

    def __create_cybox_https(self, hdict, whitelist):
        http_requests = []
        already_recorded = {}

        for entry in hdict:
            identifier = "%s%s%s%s" % (entry['host'], entry['port'], entry['method'], entry['path'])
            if identifier in already_recorded:
                log.debug("already recorded entry: %s" % (identifier))
                continue
            already_recorded[identifier] = True

            http_session = HTTPSession()
            http_session.http_request_response = self.__create_cybox_http_request_response(entry, whitelist)
            if not http_session.http_request_response:
                log.debug("no request response object created ...")
                continue
            http_requests.append(http_session)
        return http_requests

    def __create_cybox_domains(self, hdict, whitelist):
        domains = []
        addresses = []
        for entry in hdict:
            domain = self.__create_cybox_domain_object(entry['domain'].strip(), whitelist)
            if not domain:
                continue
            if entry['ip'] != '':
                ip_obj = self.__create_cybox_ip_address_object(entry['ip'].strip(), whitelist)
                if not ip_obj:
                    continue
                domain.add_related(ip_obj, "Resolved_To", inline=False)
                addresses.append(ip_obj)
            domains.append(domain)
        return domains, addresses

    def __create_cybox_dns_queries(self, hdict, whitelist):
        queries = []
        already_requested = []

        for entry in hdict:
            if entry['request'].strip() not in already_requested:
                question = DNSQuestion()
                question.qname = self.__create_cybox_domain_object(entry['request'].strip(), whitelist)
                if not question.qname:
                    continue
                question.qtype = String(entry['type'].strip())
                question.qclass = String("IN")
                query = DNSQuery()
                query.successful = False
                query.question = question
                queries.append(query)
                already_requested.append(entry['request'].strip())
        return queries

    def create_cybox_object(self, jdict, whitelist, config):
        listObservables = []
        NS = cybox.utils.Namespace("cert.siemens.com", "siemens_cert")
        cybox.utils.set_id_namespace(NS)

        """ store information about malware binary that was analyzed """
        if 'target' in jdict and 'category' in jdict['target'] and jdict['target']['category'] == 'file':
            log.debug("handling File information ...")
            main_file_object = self.__create_cybox_main_file(jdict['target']['file'])
        elif 'target' in jdict and 'category' in jdict['target'] and jdict['target']['category'] == 'url':
            log.warning("Not a file analysis report! URL reports not handled")
            return
        else:
            log.error("No target information in report ... skipping")
            return

        """ store extended information about malware file """
        if 'static' in jdict:
            log.debug("handling extended File information ...")
            win_executable_extension = self.__create_cybox_win_executable(jdict['target']['file'], jdict['static'])
            if win_executable_extension:
                main_file_object.add_related(win_executable_extension, "Characterized_By", inline=False)
            win_executable_extension = [win_executable_extension]
        else:
            log.warning("No extended File information found")
            win_executable_extension = []

        """ store domains connected to """
        if 'network' in jdict and 'domains' in jdict['network']:
            log.debug("handling Domain information ...")
            domains, addresses = self.__create_cybox_domains(jdict['network']['domains'], whitelist)
            for dom in domains:
                main_file_object.add_related(dom, 'Connected_To', inline=False)
        else:
            domains = []
            addresses = []

        """ store http session information """
        if 'network' in jdict and 'http' in jdict['network']:
            log.debug("handling HTTP information ...")
            http_requests = self.__create_cybox_https(jdict['network']['http'], whitelist)
            for session in http_requests:
                main_file_object.add_related(session, 'Connected_To', inline=False)
        else:
            http_requests = []

        """ store dns queries information about the malware """
        if 'network' in jdict and 'dns' in jdict['network']:
            log.debug("handling DNS information ...")
            queries = self.__create_cybox_dns_queries(jdict['network']['dns'], whitelist)
            for query in queries:
                main_file_object.add_related(query, 'Connected_To', inline=False)
        else:
            queries = []

        """ store information about dropped files """
        if 'dropped' in jdict:
            log.debug('handling dropped files ...')
            dropped = self.__create_cybox_dropped_files(jdict['dropped'], jdict['target']['file']['sha256'])
            for drop in dropped:
                main_file_object.add_related(drop, 'Dropped', inline=False)
        else:
            dropped = []

        """ create observables """
        o = Observables([main_file_object]+win_executable_extension+domains+addresses+http_requests+dropped+queries)
        """ create markings """
        spec = MarkingSpecificationType()
        spec.set_Controlled_Structure("//node()")
        tlpmark = TLPMarkingStructureType()
        if config:
            tlpmark.set_color(config["color"])
        else:
            tlpmark.set_color("AMBER")
        spec.set_Marking_Structure([tlpmark])
        """ generate stix id with siemens namespace """
        if config:
            stix_id_generator = stix.utils.IDGenerator(namespace=config["namespace"])
        else:
            stix_id_generator = stix.utils.IDGenerator(namespace="siemens_cert")
        """ create stix package """
        stix_id = stix_id_generator.create_id()
        stix_package = STIXPackage(observables=o, id_=stix_id)
        stix_header = STIXHeader()
        stix_header.title = "Analysis report: %s" % (str(main_file_object.file_name).decode('utf8', errors='xmlcharrefreplace'))
        if 'info' in jdict and 'started' in jdict['info']:
            sandbox_report_date = dateparser.parse(jdict['info']['started']+' CET').isoformat()
        else:
            sandbox_report_date = datetime.datetime.now(pytz.timezone('Europe/Berlin')).isoformat()
        stix_header.description = 'Summarized analysis results for file "%s" with MD5 hash "%s" created on %s.' % (str(main_file_object.file_name).decode('utf8', errors='xmlcharrefreplace'), main_file_object.hashes.md5, sandbox_report_date)
        stix_header.handling = Handling([spec])
        stix_information_source = InformationSource()
        stix_information_source.time = Time(produced_time=sandbox_report_date)
        stix_information_source.tools = ToolInformationList([ToolInformation(tool_name="SIEMENS-ANALYSIS-TOOL-ID-12", tool_vendor="")])
        stix_header.information_source = stix_information_source
        stix_package.stix_header = stix_header
        """ write result xml file """
        fp = open(os.path.join(self.reports_path, "report.stix-%s.xml" % (sandbox_report_date)), 'w')
        if config:
            fp.write(stix_package.to_xml({config["xmlns"]: config["namespace"]}))
        else:
            fp.write(stix_package.to_xml({'cert.siemens.com': 'siemens_cert'}))
        fp.close()
        return

    def __init_whitelists(self, config=None, dbtype="whitelistdatabase"):
        whitelist = {}
        whitelist['network_whitelist'] = []
        whitelist['topleveldomain_whitelist'] = []
        whitelist['specific_whitelist'] = []

        if not config:
            return whitelist

        try:
            conn_string = "host='%s' dbname='%s' user='%s' password='%s'" % (config['pghost'], config['dbname'], config['pguser'], config['pgpass'])
            conn = psycopg2.connect(conn_string)
            conn.set_isolation_level(0)
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        except StandardError as e:
            log.error("__init_whitelists: %s" % (e))
            return whitelist

        if conn:
            """ get whitelisted network ranges """
            cursor.execute("SELECT * FROM whitelist.networks")
            network_rows = cursor.fetchall()
            for nrow in network_rows:
                net = nrow['network']
                whitelist['network_whitelist'].append(IPRange(net))
            """ get whitelisted top-level domains """
            cursor.execute("SELECT * FROM whitelist.topleveldomains")
            tdl_rows = cursor.fetchall()
            for tdlrow in tdl_rows:
                whitelist['topleveldomain_whitelist'].append(tdlrow['tdl'])
            """ get specific whitelist entries """
            cursor.execute("SELECT * FROM whitelist.specific")
            specific_rows = cursor.fetchall()
            for srow in specific_rows:
                whitelist['specific_whitelist'].append(srow['value'])
        else:
            log.error("failed connecting to whitelist database")
            if cursor != None:
                cursor.close()
            if conn != None:
                conn.close()
            return whitelist
        if cursor != None:
            cursor.close()
        if conn != None:
            conn.close()

        return whitelist

    def run(self, results):
        if not HAVE_STIX:
            log.error("Unable to import cybox and stix (install with `pip install cybox/stix`)")
            return None
        whitelist = self.__init_whitelists(config=self.options)
        self.create_cybox_object(results, whitelist, self.options)
