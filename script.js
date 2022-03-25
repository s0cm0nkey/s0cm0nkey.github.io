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
        	  window.open(links[buttonValue]+userObject);
            }
}
function standAlone(buttonValue)
{
        	  const links = [];
        	  links["DNSBL"]="https://www.dnsbl.info/dnsbl-database-check.php";
            links["CymruIPBulkLookup"]="https://reputation.team-cymru.com/";
            links["InfoByIPBulkLookup"]="https://www.infobyip.com/ipbulklookup.php";
            links["IPVoid"]="https://www.ipvoid.com/ip-blacklist-check/";
            links["IPSpamList"]="http://www.ipspamlist.com/ip-lookup/";
         	  window.open(links[buttonValue]);
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
               windows.open("https://www.blocklist.de/en/search.html?action=search&send=start+search&ip="+userObject);
          }
}            
