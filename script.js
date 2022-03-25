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
        	  links["Hurricane Electric"]="https://bgp.he.net/search?commit=Search&search[search]=";
                    links["VirusTotal"]="https://www.virustotal.com/gui/search/";
               links["Cisco Talos"]="https://www.talosintelligence.com/reputation_center/lookup?search=";
               links["MXToolbox Supertool"]="https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a";
               links["MultiRBL"]="https://multirbl.valli.org/lookup/";
        	  window.open(links[buttonValue]+userObject);
            }
}
