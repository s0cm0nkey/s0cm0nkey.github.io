function validObject(str) {
     var pattern = new RegExp('^(https?:\\/\\/)?'+ // protocol
       '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|'+ // domain name
       '((\\d{1,3}\\.){3}\\d{1,3}))'+ // OR ip (v4) address
       '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*'+ // port and path
       '(\\?[;&a-z\\d%_.~+=-]*)?'+ // query string
       '(\\#[-a-z\\d_]*)?$','i'); // fragment locator
      return !!pattern.test(str);
     }
function buttonOpen(buttonValue)
        {
        	userObject=document.getElementById("Object").value;
        	if(validObject(userObject)==false)
        	{
                alert("Enter a valid Threat Object, please");
           }
        	else
        	{
        	  const links = [];
            /* Multi RBL Tools */
        	  links["Hurricane Electric"]="https://bgp.he.net/search?commit=Search&search[search]=";
            links["VirusTotal"]="https://www.virustotal.com/gui/search/";
            links["Cisco Talos"]="https://www.talosintelligence.com/reputation_center/lookup?search=";
            links["MXToolbox Supertool"]="https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a";
            links["MultiRBL"]="https://multirbl.valli.org/lookup/";
            /* IP Blacklist Checkers*/
            links["AbuseIPDB"]="https://www.abuseipdb.com/check/";
            links["Blocklist.de"]="https://www.blocklist.de/en/search.html?action=search&send=start+search&ip=";
            links["ProjectHoneypot"]="https://www.projecthoneypot.org/ip_";
            links["GreynoiseIP"]="https://www.greynoise.io/viz/ip/";
            /* VPN Checker */
            links["IPQualityScoreVPN"]="https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/";
            /* Domain Blacklist Checkers */
            links["URLVoid"]="https://www.urlvoid.com/scan/";
            links["SecuriSiteCheck"]="https://sitecheck.sucuri.net/?scan=";
            links["MalwareDomains"]="https://www.malwaredomainlist.com/mdl.php?colsearch=All&quantity=50&search=";
            /* Threat Enrichment Tools */
            links["ThreatCrowd"]="https://www.threatcrowd.org/pivot.php?data=";
            links["ThreatFox"]="https://threatfox.abuse.ch/browse.php?search=ioc%3A";
            links["ThreatIntelPlatform"]="https://threatintelligenceplatform.com/report/";
            links["RiskIQ"]="https://community.riskiq.com/research?query=";
            links["Malcode"]="https://malc0de.com/database/index.php?search=";
            links["Abusix"]="https://lookup.abusix.com/search?q=";
            links["SANS"]="https://secure.dshield.org/ipinfo.html?ip=";
            /* Cyber Search Tools */
            links["Shodan"]="https://www.shodan.io/search?query=";
            links["Spyse"]="https://spyse.com/search?query=";
            links["Maltiverse"]="https://maltiverse.com/search;query=";
            links["Onyphe"]="https://www.onyphe.io/search/?query=";
            links["IntelX"]="https://intelx.io/?s=";
            links["Natlas"]="https://natlas.io/search?query=";
            links["ThreatEncyclopedia"]="https://www.trendmicro.com/vinfo/us/threat-encyclopedia/search/";
            links["BinaryEdge"]="https://app.binaryedge.io/services/query?query=";
            links["Censys"]="https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=";
            links["LeakIX"]="https://leakix.net/search?q=";
            links["FullHunt"]="https://fullhunt.io/search?query=domain%3A";
            /* File Tools */
            links["BazaarMD5"]="https://bazaar.abuse.ch/browse.php?search=md5%3A";
            links["BazaarSHA256"]="https://bazaar.abuse.ch/browse.php?search=sha256%3A";
            links["Manalyzer"]="https://manalyzer.org/report/";
            links["WinBinDex"]="https://winbindex.m417z.com/?file=";
            links["EchoTrail"]="https://www.echotrail.io/insights/search/";
            links["Malshare"]="https://malshare.com/search.php?query=";
            /* Sandboxes */
            links["HybridAnalysis"]="https://www.hybrid-analysis.com/search?query=";
            links["JoeSandbox"]="https://www.joesandbox.com/search?q=";
            links["GateWatcher"]="https://intelligence.gatewatcher.com/sample_search/?q=";
            links["TRIAGE"]="https://tria.ge/s?q=";
            /* Google Dorks */
            links["DorkIndex"]="https://www.google.ca/search?q=intitle:index.of+site:";
            links["DorkLogin"]="https://www.google.ca/search?q=inurl:username+OR+inurl:password+OR+inurl:login+OR+inurl:root+OR+inurl:admin+OR+inurl:adminlogin+OR+inurl:cplogin+OR+inurl:weblogin+OR+inurl:quicklogin+OR+inurl:wp-admin+OR+inurl:wp-login+OR+inurl:portal+OR+inurl:userportal+OR+inurl:loginpanel+OR+inurl:memberlogin+OR+inurl:remote+OR+inurl:dashboard+OR+inurl:auth+OR+inurl:exchange+OR+inurl:ForgotPassword+OR+inurl:test+site:";
            links["DorkBackdoor"]="https://www.google.ca/search?q=inurl:shell+OR+inurl:backdoor+OR+inurl:wso+OR+inurl:cmd+OR+shadow+OR+passwd+OR+boot.ini+OR+inurl:backdoor+site:";
            links["DorkSetup"]="https://www.google.ca/search?q=inurl:readme+OR+inurl:license+OR+inurl:install+OR+inurl:setup+OR+inurl:config+site:";
            links["DorkWordpress"]="https://www.google.ca/search?q=inurl:wp-+OR+inurl:plugin+OR+inurl:upload+OR+inurl:download+OR+inurl:wp-content+OR+inurl:wp-includes+site:";
            links["DorkRedirects"]="https://www.google.ca/search?q=inurl:redir+OR+inurl:url+OR+inurl:redirect+OR+inurl:return+OR+inurl:src=http+OR+inurl:r=http+site:";
            links["DorkFiles"]="https://www.google.ca/search?q=ext:cgi+OR+ext:php+OR+ext:asp+OR+ext:aspx+OR+ext:jsp+OR+ext:jspx+OR+ext:swf+OR+ext:fla+OR+ext:xml+OR+ext:conf+OR+ext:cnf+OR+ext:reg+OR+ext:inf+OR+ext:rdp+OR+ext:cfg+OR+ext:txt+OR+ext:ora+OR+ext:ini+OR+ext:swf+site:";
            links["DorkDocs"]="https://www.google.ca/search?q=ext:doc+OR+ext:docx+OR+ext:csv+OR+ext:pdf+OR+ext:txt+OR+ext:log+OR+ext:bak+OR+ext:bkf+OR+ext:bkp+OR+ext:old+OR+ext:backup+OR+ext:xls+OR+ext:xlsx+OR+ext:ppt+OR+ext:pptx+OR+ext:dat+site:";
            links["DorkDb"]="https://www.google.ca/search?q=ext:sql+OR+ext:dbf+OR+ext:mdb+site:";
            links["DorkMisc"]="https://www.google.ca/search?q=inurl:phpinfo+OR+inurl:htaccess+OR+ext:git+site:";
            links["DorkStruts"]="https://www.google.ca/search?q=ext:action+OR+struts+site:";
            links["DorkPastebin"]="https://www.google.ca/search?q=site:pastebin.com+";
            /* Subdomains */
            links["DorkSub"]="https://www.google.ca/search?q=site:*.";
            links["DorkSubsub"]="https://www.google.ca/search?q=site:*.*.";
            links["crt.sh"]="https://crt.sh/?q=%25.";
            links["SpyseSubs"]="https://spyse.com/tools/subdomain-finder/search?query=";
            /* Content References */
            links["Github"]="https://github.com/search?q=";
            links["Gitlab"]="https://gitlab.com/explore?name=";
            links["StackOverflow"]="https://stackoverflow.com/search?q=";
            links["SourceForge"]="https://sourceforge.net/directory/?clear&q=";
            links["OpenBug"]="https://www.openbugbounty.org/search/?search=";
            links["FireBounty"]="https://firebounty.com/?sort=created_at&order=desc&search_field=name&search=";
            links["GrepApp"]="https://grep.app/search?q=";
            links["Searchcode"]="https://searchcode.com/?q=";
            /* Recon Tools */
            links["WHOIS"]="https://who.is/whois/";
            links["Whoxy"]="https://www.whoxy.com/";
            links["RDAP"]="https://client.rdap.org/?type=domain&object=";
            links["DomainBigData"]="https://domainbigdata.com/";
            links["VDNSReverseIP"]="https://viewdns.info/reverseip/?host=";
            links["VDNSReverseWHOIS"]="https://viewdns.info/reversewhois/?q=";
            links["VDNSHistory"]="https://viewdns.info/iphistory/?q=";
            links["Spyonweb"]="https://spyonweb.com/";
            links["AnalyzeID"]="https://analyzeid.com/id/";
            links["Builtwith"]="https://builtwith.com/";
            links["HunterIO"]="https://hunter.io/try/search/";
            links["Linkody"]="http://bc.linkody.com/en/seo-tools/free-backlink-checker/";
            links["VisualSiteMapper"]="http://visualsitemapper.com/map/";
            links["Wappalyzer"]="https://www.wappalyzer.com/lookup/";
            /* Security Scanners */
            links["Mozilla"]="https://observatory.mozilla.org/analyze/";
            links["Netcraft"]="https://sitereport.netcraft.com/?url=";
            links["SecurityHeaders"]="https://securityheaders.com/?q=";
            links["SSLLabs"]="https://www.ssllabs.com/ssltest/analyze.html?d=";
            /* DNS Tools */
            links["VDNSReport"]="https://viewdns.info/dnsreport/?domain=";
            links["VDNSRecords"]="https://viewdns.info/dnsrecord/?domain=";
            links["DNSSEC"]="https://viewdns.info/dnssec/?domain=";
            links["DNSlytics"]="https://dnslytics.com/search?q=";
            /* Breach/Paste */
            links["Dehashed"]="https://www.dehashed.com/search?query=";
            /* Intel Platforms */
            links["Xforce"]="https://exchange.xforce.ibmcloud.com/search/";
            window.open(links[buttonValue]+userObject);
            }
}
function standAlone(buttonValue)
{
        	  const links = [];
     /* Standalone IP tools */
        	  links["DNSBL"]="https://www.dnsbl.info/dnsbl-database-check.php";
            links["CymruIPBulkLookup"]="https://reputation.team-cymru.com/";
            links["InfoByIPBulkLookup"]="https://www.infobyip.com/ipbulklookup.php";
            links["IPVoid"]="https://www.ipvoid.com/ip-blacklist-check/";
            links["IPSpamList"]="http://www.ipspamlist.com/ip-lookup/";
            links{"Exonerator"]="https://metrics.torproject.org/exonerator.html";
     /* Standalone domain tools */
            links["URLScan"]="https://urlscan.io/";
            links["MergiTools"]="https://megritools.com/blacklist-lookup";
            links["Zulu"]="https://zulu.zscaler.com/";
            links["Quttera"]="https://quttera.com/website-malware-scanner";
            links["PhishTank"]="https://www.phishtank.com/";
            links["LOTS"]="https://lots-project.com/";
     /* Threat Enrichment Tools */
            links["BrightCloud"]="https://www.brightcloud.com/tools/url-ip-lookup.php";
            links["MetaDefender"]="https://metadefender.opswat.com/";
            links["Pulsedive"]="https://pulsedive.com/";
            links["ThreatShare"]="https://threatshare.io/malware/";
            links["PhishStats"]="https://phishstats.info/";
            links["TweetIOC"]="http://tweettioc.com/search";
     /* Cyber Search Tools */
            links["Synapsint"]="https://synapsint.com/";
            links["Guardicore"]="https://threatintelligence.guardicore.com/";
            links["ThreatMiner"]="https://www.threatminer.org/index.php";
     /* File Tools */
            links["TalosFile"]="https://talosintelligence.com/talos_file_reputation";
            links["CymruHash"]="https://hash.cymru.com:";
            links["Valkyrie"]="https://valkyrie.comodo.com/";
            links["Strontic"]="https://strontic.github.io/xcyclopedia/";
            links["Filesec"]="https://filesec.io/";
     /* Sandboxes */
            links["AnyRun"]="https://app.any.run/submissions";
            links["IntezerAnalyze"]="https://analyze.intezer.com/";
            links["IrisH"]="https://iris-h.services/pages/submit";
            links["Pikker"]="https://sandbox.pikker.ee/analysis/search/";
            links["Inquest"]="https://labs.inquest.net/dfi";
            links["FileScan"]="https://www.filescan.io/scan";
     /* DNS Tools */
            links["DNSDumpster"]="https://dnsdumpster.com/";
            links["Dig"]="https://toolbox.googleapps.com/apps/dig/";
     /* Subdomains */
            links["Crobat"]="https://omnisint.io/";
            links["PTToolsSubs"]="https://pentest-tools.com/information-gathering/find-subdomains-of-domain";
     /* Web Based Scanning tools */
            links["CSPEval"]="https://csp-evaluator.withgoogle.com/";
            links["Snyk"]="https://snyk.io/website-scanner/";
            links["WhatCMS"]="https://whatcms.org/";
     /* Breach/Paste */
            links["HIBP"]="https://haveibeenpwned.com/";
            links["LeakLookup"]="https://leak-lookup.com/";
            links["BreachDirectory"]="https://breachdirectory.org/";
            links["LeakedSite"]="https://leaked.site/";
            links["WeLeakInfo"]="https://weleakinfo.to/";
            links["PSBDump"]="https://psbdmp.ws/";
            links["Pastebin.ga"]="https://pastebin.ga/";
            links["RedHunt"]="https://redhuntlabs.com/online-ide-search";
            window.open(links[buttonValue]);
}
function adGuard()
{
     const links = [];
     window.open("https://reports.adguard.com/en/"+userObject+"/report.html");
}
function Robots()
{
     const links =[];
     window.open("https://"+userObject+"/robots.txt");
}
function SystemLookup()
{
     const links = [];
     window.open("https://www.systemlookup.com/search.php?list=&type=filename&search="+userObject+"&s=");
}
function NerdyData()
{
     const links =[];
     window.open("https://www.nerdydata.com/reports/new?search=%7B%22all%22%3A%5B%7B%22type%22%3A%22code%22,%22value%22%3A%22"+userObject+"%22%7D%5D,%22any%22%3A%5B%5D,%22none%22%3A%5B%5D%7D");
}
function multiBlacklistOpen()
{
     userObject=document.getElementById("Object").value;
        	if(validObject(userObject)==false)
        	{
                alert("Enter a valid Threat Object, please");
           }
        	else
        	{
               const links = [];
               window.open("https://bgp.he.net/search?commit=Search&search[search]="+userObject);
               window.open("https://www.virustotal.com/gui/search/"+userObject);
               window.open("https://www.talosintelligence.com/reputation_center/lookup?search="+userObject);
               window.open("https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a"+userObject);
               window.open("https://multirbl.valli.org/lookup/"+userObject);
          }
}            
function IPBlacklistOpen()
{
     userObject=document.getElementById("Object").value;
        	if(validObject(userObject)==false)
        	{
                alert("Enter a valid Threat Object, please");
           }
        	else
        	{
               const links = [];
               window.open("https://www.abuseipdb.com/check/"+userObject);
               window.open("https://www.blocklist.de/en/search.html?action=search&send=start+search&ip="+userObject);
               window.open("https://www.projecthoneypot.org/ip_"+userObject);
               window.open("https://www.greynoise.io/viz/ip/"+userObject);
          }
}            
function domainBlacklistOpen()
{
     userObject=document.getElementById("Object").value;
        	if(validObject(userObject)==false)
        	{
                alert("Enter a valid Threat Object, please");
           }
        	else
        	{
               const links = [];
               window.open("https://www.urlvoid.com/scan/"+userObject);
               window.open("https://reports.adguard.com/en/"+userObject+"/report.html");
               window.open("https://sitecheck.sucuri.net/?scan="+userObject);
               window.open("https://www.malwaredomainlist.com/mdl.php?colsearch=All&quantity=50&search="+userObject);
          }
}            
function ThreatEnrichmentOpen()
{
     userObject=document.getElementById("Object").value;
        	if(validObject(userObject)==false)
        	{
                alert("Enter a valid Threat Object, please");
           }
        	else
        	{
               const links = [];
               window.open("https://www.threatcrowd.org/pivot.php?data="+userObject);
               window.open("https://threatfox.abuse.ch/browse.php?search=ioc%3A"+userObject);
               window.open("https://threatintelligenceplatform.com/report/"+userObject);
               window.open("https://community.riskiq.com/research?query="+userObject);
               window.open("https://malc0de.com/database/index.php?search="+userObject);
               window.open("https://lookup.abusix.com/search?q="+userObject);
               window.open("https://secure.dshield.org/ipinfo.html?ip="+userObject);
          }
} 
function CyberSearchOpen()
{
     userObject=document.getElementById("Object").value;
        	if(validObject(userObject)==false)
        	{
                alert("Enter a valid Threat Object, please");
           }
        	else
        	{
               const links = [];
               window.open("https://www.shodan.io/search?query="+userObject);
               window.open("https://spyse.com/search?query="+userObject);
               window.open("https://maltiverse.com/search;query="+userObject);
               window.open("https://www.onyphe.io/search/?query="+userObject);
               window.open("https://intelx.io/?s="+userObject);
               window.open("https://natlas.io/search?query="+userObject);
               window.open("https://www.trendmicro.com/vinfo/us/threat-encyclopedia/search/"+userObject);
               window.open("https://app.binaryedge.io/services/query?query="+userObject);
               window.open("https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q="+userObject);
               window.open("https://leakix.net/search?q="+userObject);
               window.open("https://fullhunt.io/search?query=domain%3A"+userObject);
          }
} 
function FileRepOpen()
{
               const links = [];
               window.open("https://www.virustotal.com/gui/search/"+userObject);
               window.open("https://threatfox.abuse.ch/browse.php?search=ioc%3A"+userObject);
               window.open("https://maltiverse.com/search;query="+userObject);
               window.open("https://www.trendmicro.com/vinfo/us/threat-encyclopedia/search/"+userObject);
               window.open("https://malshare.com/search.php?query="+userObject);
}
function SandboxOpen()
{
               const links =[];
               window.open("https://www.hybrid-analysis.com/search?query="+userObject);
               window.open("https://www.joesandbox.com/search?q="+userObject);
               window.open("https://intelligence.gatewatcher.com/sample_search/?q="+userObject);
               window.open("https://tria.ge/s?q="+userObject);
}
function GoogleDorkOpen()
{
     const links =[];
     window.open("https://www.google.ca/search?q=intitle:index.of+site:"+userObject);
     window.open("https://www.google.ca/search?q=inurl:username+OR+inurl:password+OR+inurl:login+OR+inurl:root+OR+inurl:admin+OR+inurl:adminlogin+OR+inurl:cplogin+OR+inurl:weblogin+OR+inurl:quicklogin+OR+inurl:wp-admin+OR+inurl:wp-login+OR+inurl:portal+OR+inurl:userportal+OR+inurl:loginpanel+OR+inurl:memberlogin+OR+inurl:remote+OR+inurl:dashboard+OR+inurl:auth+OR+inurl:exchange+OR+inurl:ForgotPassword+OR+inurl:test+site:"+userObject);
     window.open("https://www.google.ca/search?q=inurl:shell+OR+inurl:backdoor+OR+inurl:wso+OR+inurl:cmd+OR+shadow+OR+passwd+OR+boot.ini+OR+inurl:backdoor+site:"+userObject);
     window.open("https://www.google.ca/search?q=inurl:readme+OR+inurl:license+OR+inurl:install+OR+inurl:setup+OR+inurl:config+site:"+userObject);
     window.open("https://www.google.ca/search?q=inurl:wp-+OR+inurl:plugin+OR+inurl:upload+OR+inurl:download+OR+inurl:wp-content+OR+inurl:wp-includes+site:"+userObject);
     window.open("https://www.google.ca/search?q=inurl:redir+OR+inurl:url+OR+inurl:redirect+OR+inurl:return+OR+inurl:src=http+OR+inurl:r=http+site:"+userObject);
     window.open("https://www.google.ca/search?q=ext:cgi+OR+ext:php+OR+ext:asp+OR+ext:aspx+OR+ext:jsp+OR+ext:jspx+OR+ext:swf+OR+ext:fla+OR+ext:xml+OR+ext:conf+OR+ext:cnf+OR+ext:reg+OR+ext:inf+OR+ext:rdp+OR+ext:cfg+OR+ext:txt+OR+ext:ora+OR+ext:ini+site:"+userObject);
     window.open("https://www.google.ca/search?q=ext:doc+OR+ext:docx+OR+ext:csv+OR+ext:pdf+OR+ext:txt+OR+ext:log+OR+ext:bak+OR+ext:bkf+OR+ext:bkp+OR+ext:old+OR+ext:backup+OR+ext:xls+OR+ext:xlsx+OR+ext:ppt+OR+ext:pptx+OR+ext:dat+site:"+userObject);
     window.open("https://www.google.ca/search?q=ext:sql+OR+ext:dbf+OR+ext:mdb+site:"+userObject);
     window.open("https://www.google.ca/search?q=ext:action+OR+struts+site:"+userObject);
     window.open("https://www.google.ca/search?q=site:pastebin.com+"+userObject);
     window.open("https://www.google.ca/search?q=inurl:phpinfo+OR+inurl:htaccess+OR+ext:git+site:"+userObject);
}
function Subdomains()
{
     const links =[];
     window.open("https://www.google.ca/search?q=site:*."+userObject);
     window.open("https://www.google.ca/search?q=site:*.*."+userObject);
     window.open("https://crt.sh/?q=%25."+userObject);
     window.open("https://spyse.com/tools/subdomain-finder/search?query="+userObject);
}
function ContentReference()
{
     const links =[];
     window.open("https://github.com/search?q="+userObject);
     window.open("https://gitlab.com/explore?name="+userObject);
     window.open("https://stackoverflow.com/search?q="+userObject);
     window.open("https://sourceforge.net/directory/?clear&q="+userObject);
     window.open("https://www.openbugbounty.org/search/?search="+userObject);
     window.open("https://firebounty.com/?sort=created_at&order=desc&search_field=name&search="+userObject);
     window.open("https://grep.app/search?q="+userObject);
     window.open("https://searchcode.com/?q="+userObject);
}
function ReconTools()
{
     const links =[];
     window.open("https://"+userObject+"/robots.txt");
     window.open("https://who.is/whois/"+userObject);
     window.open("https://www.whoxy.com/"+userObject);
     window.open("https://client.rdap.org/?type=domain&object="+userObject);
     window.open("https://domainbigdata.com/"+userObject);
     window.open("https://viewdns.info/reverseip/?q="+userObject);
     window.open("https://viewdns.info/reversewhois/?q="+userObject);
     window.open("https://viewdns.info/iphistory/?q="+userObject);
     window.open("https://spyonweb.com/"+userObject);
     window.open("https://analyzeid.com/id/"+userObject);
     window.open("https://www.nerdydata.com/reports/new?search=%7B%22all%22%3A%5B%7B%22type%22%3A%22code%22,%22value%22%3A%22"+userObject+"%22%7D%5D,%22any%22%3A%5B%5D,%22none%22%3A%5B%5D%7D");
     window.open("https://builtwith.com/"+userObject);
     window.open("https://hunter.io/try/search/"+userObject);
     window.open("http://bc.linkody.com/en/seo-tools/free-backlink-checker/"+userObject);
     window.open("http://visualsitemapper.com/map/"+userObject);
     window.open("https://www.wappalyzer.com/lookup/"+userObject);
}
function WebScanners()
{
     const links =[];
     window.open("https://observatory.mozilla.org/analyze/"+userObject);
     window.open("https://sitereport.netcraft.com/?url="+userObject);
     window.open("https://securityheaders.com/?q="+userObject);
     window.open("https://www.ssllabs.com/ssltest/analyze.html?d="+userObject);
}
function DNSTools()
{
     const links =[];
     window.open("https://viewdns.info/dnsreport/?domain="+userObject);
     window.open("https://viewdns.info/dnsrecord/?domain="+userObject);
     window.open("https://viewdns.info/dnssec/?domain="+userObject);
     window.open("https://dnslytics.com/search?q="+userObject);
}
function BreachPaste()
{
     const links =[];
     window.open("https://www.dehashed.com/search?query="+userObject);
}
function IntelPlatforms()
{
     const links =[];
     window.open("https://exchange.xforce.ibmcloud.com/search/"+userObject);
     window.open("https://otx.alienvault.com/browse/global/pulses?q="+userObject+"include_inactive=0&sort=-modified&page=1&indicatorsSearch="+userObject);
     window.open("https://app.threatconnect.com/#/browse?owners=2491129209,631,1930973938,1930974303,1930974969,1930975114,1930977088,1930994355,2092,8373,4070,2094,3906,9367,1284062903,3576,1931001500,1931002777,3578,7316,1931013370,1931023406,2631,1943253936,1940687317,1943254027,1940764808,9205,1946179136,1946179227,1946179318,7317,1937489682,3907,7319,1937489411,7318,2093,1937489522,2412124678,7321,1901884975,9206,7322,2120189823,1937489104,10666,7981,7324,7325,4068,7979&intelType=indicators&filters=typeName%20in%20(%22Address%22,%20%22EmailAddress%22,%20%22File%22,%20%22Host%22,%20%22URL%22,%20%22ASN%22,%20%22CIDR%22,%20%22Email%20Subject%22,%20%22Hashtag%22,%20%22Mutex%22,%20%22Registry%20Key%22,%20%22User%20Agent%22)%20and%20summary%20contains%20%22"+userObject+"%22");

}
function OTX()
{
     const links =[];
     window.open("https://otx.alienvault.com/browse/global/pulses?q="+userObject+"&sort=-modified&page=1&indicatorsSearch="+userObject);
}
function ThreatConnect()
{
     const links =[];
     window.open("https://app.threatconnect.com/#/browse?owners=2491129209,631,1930973938,1930974303,1930974969,1930975114,1930977088,1930994355,2092,8373,4070,2094,3906,9367,1284062903,3576,1931001500,1931002777,3578,7316,1931013370,1931023406,2631,1943253936,1940687317,1943254027,1940764808,9205,1946179136,1946179227,1946179318,7317,1937489682,3907,7319,1937489411,7318,2093,1937489522,2412124678,7321,1901884975,9206,7322,2120189823,1937489104,10666,7981,7324,7325,4068,7979&intelType=indicators&filters=typeName%20in%20(%22Address%22,%20%22EmailAddress%22,%20%22File%22,%20%22Host%22,%20%22URL%22,%20%22ASN%22,%20%22CIDR%22,%20%22Email%20Subject%22,%20%22Hashtag%22,%20%22Mutex%22,%20%22Registry%20Key%22,%20%22User%20Agent%22)%20and%20summary%20contains%20%22"+userObject+"%22");
}
function VPN()
{
     const links =[];
     window.open("https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/"+userObject);
}
