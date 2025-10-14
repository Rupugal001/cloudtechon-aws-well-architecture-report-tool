import os
import json

from utils.Config import Config
from utils.ArguParser import ArguParser
import constants as _C

class Framework():
    def __init__(self, data):
        self.stats = []
        self.data = data
        self.framework = type(self).__name__
        self.config = {}   # store configs for all services here

        _cli_options = ArguParser.Load()
        services = _cli_options['services'].split(',')
        # print("loading services:", services)

        for serv in services:
            serv = serv.lower()
            self.config[serv] = self.load_config(serv)

    def gateCheck(self):
        return True
    
    def getFilePath(self):
        filepath = _C.FRAMEWORK_DIR + '/' + self.framework + '/map.json'
        exists = os.path.exists(filepath)
        if not exists:
            return False
            
        return filepath
        
    def readFile(self):
        p = self.getFilePath()
        if p == False:
            print(p + " not exists, skip framework generation")
            return False
        
        self.map = json.loads(open(p).read())
    
    def getMetaData(self):
        self._hookGenerateMetaData()
        return self.map['metadata']
    
    def load_config(self, service):
        folder = service
        if service in Config.KEYWORD_SERVICES:
            folder = service + '_'

        serviceReporterJsonPath = (
            _C.SERVICE_DIR + '/' + folder + '/' + service + '.reporter.json'
        )

        if not os.path.exists(serviceReporterJsonPath):
            print("[Fatal] " + serviceReporterJsonPath + " not found")
            return {}

        with open(serviceReporterJsonPath) as f:
            service_config = json.load(f)

        if not service_config:
            raise Exception(serviceReporterJsonPath + " does not contain valid JSON")

        with open(_C.GENERAL_CONF_PATH) as f:
            generalConfig = json.load(f)

        return {**service_config, **generalConfig}

        
    # To be overwrite if needed
    def _hookGenerateMetaData(self):
        pass

    def _hookPostItemActivity(self, title, section, checks, comp):
        return title, section, checks, comp

    def _hookPostItemsLoop(self):
        pass
    
    # ['Main', 'ARC-003', 0, '[iam,rootMfaActive] Root ID, Admin<br>[iam.passwordPolicy] sss', 'Link 1<br>Link2']
    def generateMappingInformation(self):
        ## Not Available, Comply, Not Comply
        summ = {}
        outp = []
        
        emptyCheckDefaultMsg = ""
        if 'emptyCheckDefaultMsg' in self.map['metadata']:
            emptyCheckDefaultMsg = self.map['metadata']['emptyCheckDefaultMsg']
        
        for title, sections in self.map['mapping'].items():
            # outp.append(self.formatTitle(title))
            # [Manual, Compliant, Not Comply]
            if not title in summ:
                summ[title] = [0,0,0]
                
            comp = 1
            for section, maps in sections.items():
                arr = []
                checks = links = ''
                if len(maps) == 0:
                    # outp.append("Framework does not has relevant check, manual intervention required")
                    comp = 0
                    checks = emptyCheckDefaultMsg
                
                else: 
                    pre = []
                    for _m in maps:
                        tmp = self.getContent(_m)
                        pre.append(tmp)
                    # if self.framework == 'WAFS':
                    #     print(f"PRE: {pre}")
                    checks, links, comp = self.formatCheckAndLinks(pre)
                title, section, checks, comp = self._hookPostItemActivity(title, section, checks, comp)
                
                outp.append([title, section, comp, checks, links])
                pos = comp
                if(comp==-1):
                    pos = 2
                
                summ[title][pos] += 1    
        
        self._hookPostItemsLoop()
        # if self.framework == 'WAFS':
        #     print("Framework stats:", summ)
        self.stats = summ
        return outp
    
    def generateGraphInformation(self):
        outp = {}
        _m = 0  # manual
        _c = 0  # compliant
        _n = 0  # not comply
        for _sect, _counter in self.stats.items():
            _m += _counter[0]
            _c += _counter[1]
            _n += _counter[2]
            
        outp['mcn'] = [_m, _c, _n]
        outp['stats'] = self.stats
        return outp
    
    ## <TODO>
    def formatTitle(self, title):
        return '<h3>' + title + '</h3>'
        
    def getContent(self, _m):
        if not _m:
            return None
        
        serv, check = _m.split(".")
        
        # Special case: count check
        if check == '$length':
            cnt = self.getResourceCount(serv)
            if cnt == 0:
                return {
                    "c": serv,
                    "d": f"Need at least 1 {serv}",
                    "r": {},
                    "l": ""
                }
            else:
                return {
                    "c": f"Has {cnt} active {serv}",
                    "d": f"Has {cnt} {serv}",
                    "r": {},
                    "l": ""
                }
        
        # # Normal case: check in results
        # with open("output.json", "w") as f:
        #     json.dump(self.data, f, indent=4)
            
        # with open("config.json", "w") as f:
        #     json.dump(self.config, f, indent=4)
            
        if serv not in self.data:
            return {
            "c": check,
            "d": f"Service {serv} not available in scan results",
            "r": {},
            "l": ""
        }
        elif serv in self.data and check in self.data[serv]['summary']:
            tmp = self.data[serv]['summary'][check]
            if tmp['__status'] == -1:
                ln = tmp.get('__links', [])
                if not ln:
                    print("###########:", check)
                return {
                    "c": check,
                    "d": tmp['shortDesc'],
                    "r": tmp.get('__affectedResources', {}),
                    "l": "<br>".join(ln)
                }
            elif tmp['__status'] == 1:
                return {"c": check}
            
        # Check in config but not in results
        elif (serv in self.data and check not in self.data[serv]['summary']) and check in self.config[serv]:
            if self.framework == 'WAFR' :
                return { 'c': check}
            # print(f"[Warning] {serv}.{check} not found in scan results, but available in config")
            return {
                "c": check, 
                # "d": "Configured but no data or Service not available", 
                "d": f"{serv} Configured but no data or Need at least 1 {serv}", 
                "r": {}, 
                "l": ""
                }
        
        # Not found at all
        return {
            "c": check,
            "d": "Check not available in scan results",
            "r": {},
            "l": ""
        }
            
    def getResourceCount(self, serv):
        d = Config.get('cli_services', {})
        if serv in d:
            return d[serv]
        else:
            return 0
            
    def formatCheckAndLinks(self, packedData):
        links = []
        comp = 1
        
        checks = ["<dl>"]
        for v in packedData:
            if "r" in v:
                tmp = ['<ul>']
                for _reg, _affected in v['r'].items():
                    tmp.append("<li><b>[" + _reg + "]</b>" + ", ".join(_affected) + "</li>")
                
                tmp.append("</ul>")
                    
                c = "<dt class='text-danger'><i class='fas fa-times'></i> [{}] - {}</dt>{}</dd>".format(v['c'], v['d'], "".join(tmp))
                links.append(v['l'])
                comp = -1
            else:
                c = "<dt class='text-success'><i class='fas fa-check'></i> [{}]</i></dt>".format(v['c'])
                
            checks.append(c)
        checks.append("</dl>")
        
        return ["".join(checks), "<br>".join(links), comp]
    
    def _hookPostBuildContentDetail(self):
        pass