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
            /* Domain Blacklist Checkers */
            links["URLVoid"]="https://www.urlvoid.com/scan/";
            links["SecuriSiteCheck"]="https://sitecheck.sucuri.net/?scan=";
            links["MalwareDomains"]="https://www.malwaredomainlist.com/mdl.php?colsearch=All&quantity=50&search=";
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
            links["Quttera"]"https://quttera.com/website-malware-scanner";
            links["PhishTank"]"https://www.phishtank.com/";
            links["LOTS"]="https://lots-project.com/";
         	  window.open(links[buttonValue]);
}
function adGuard()
{
     const links = [];
     window.open("https://reports.adguard.com/en/"+userObject+"/report.html");
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
