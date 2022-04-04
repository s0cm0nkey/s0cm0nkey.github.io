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
            links["DorkLogin"]="https://www.google.ca/search?q=site:username+OR+password+OR+login+OR+root+OR+admin+site:";
            links["DorkBackdoor"]="https://www.google.ca/search?q=site:inurl:shell+OR+inurl:backdoor+OR+inurl:wso+OR+inurl:cmd+OR+shadow+OR+passwd+OR+boot.ini+OR+inurl:backdoor+site:";
            links["DorkSetup"]="https://www.google.ca/search?q=site:inurl:readme+OR+inurl:license+OR+inurl:install+OR+inurl:setup+OR+inurl:config+site:";
            links["DorkWordpress"]="https://www.google.ca/search?q=site:inurl:wp-+OR+inurl:plugin+OR+inurl:upload+OR+inurl:download+site:";
            links["DorkRedirects"]="https://www.google.ca/search?q=site:inurl:redir+OR+inurl:url+OR+inurl:redirect+OR+inurl:return+OR+inurl:src=http+OR+inurl:r=http+site:";
            links["DorkFiles"]="https://www.google.ca/search?q=ext:cgi+OR+ext:php+OR+ext:asp+OR+ext:aspx+OR+ext:jsp+OR+ext:jspx+OR+ext:swf+OR+ext:fla+OR+ext:xml+site:";
            links["DorkDocs"]="https://www.google.ca/search?q=ext:doc+OR+ext:docx+OR+ext:csv+OR+ext:pdf+OR+ext:txt+OR+ext:log+OR+ext:bak+site:";
            links["DorkStruts"]="https://www.google.ca/search?q=ext:action+OR+struts+site:";
            links["DorkPastebin"]="https://www.google.ca/search?q=site:pastebin.com+";
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
            window.open(links[buttonValue]);
}
function adGuard()
{
     const links = [];
     window.open("https://reports.adguard.com/en/"+userObject+"/report.html");
}
function SystemLookup()
{
     const links = [];
     window.open("https://www.systemlookup.com/search.php?list=&type=filename&search="+userObject+"&s=");
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
     window.open("https://www.google.ca/search?q=site:username+OR+password+OR+login+OR+root+OR+admin+site:"+userObject);
     window.open("https://www.google.ca/search?q=site:inurl:shell+OR+inurl:backdoor+OR+inurl:wso+OR+inurl:cmd+OR+shadow+OR+passwd+OR+boot.ini+OR+inurl:backdoor+site:"+userObject);
     window.open("https://www.google.ca/search?q=site:inurl:readme+OR+inurl:license+OR+inurl:install+OR+inurl:setup+OR+inurl:config+site:"+userObject);
     window.open("https://www.google.ca/search?q=site:inurl:wp-+OR+inurl:plugin+OR+inurl:upload+OR+inurl:download+site"+userObject);
     window.open("https://www.google.ca/search?q=site:inurl:redir+OR+inurl:url+OR+inurl:redirect+OR+inurl:return+OR+inurl:src=http+OR+inurl:r=http+site:"+userObject);
     window.open("https://www.google.ca/search?q=ext:cgi+OR+ext:php+OR+ext:asp+OR+ext:aspx+OR+ext:jsp+OR+ext:jspx+OR+ext:swf+OR+ext:fla+OR+ext:xml+site:"+userObject);
     window.open("https://www.google.ca/search?q=ext:doc+OR+ext:docx+OR+ext:csv+OR+ext:pdf+OR+ext:txt+OR+ext:log+OR+ext:bak+site:"+userObject);
     window.open("https://www.google.ca/search?q=ext:action+OR+struts+site:"+userObject);
     window.open("https://www.google.ca/search?q=site:pastebin.com+"+userObject);
}
     
