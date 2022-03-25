function validURL(str) {
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

        	userURL=document.getElementById("url").value;

        	if(validURL(userURL)==false)
        	{
               	 alert("Enter a valid URL, please");
        		
           }
        	else
        	{

        	  const links = [];
        	  links["HurricaneElectric"]="https://bgp.he.net/search?commit=Search&search%5Bsearch%5D=";
        	  window.open(links[buttonValue]+userURL);
        	  
            }
}


function buttonOpen(buttonValue)
        {

        	userURL=document.getElementById("url").value;

        	if(validURL(userURL)==false)
        	{
               	 alert("Enter a valid URL, please");
        		
           }
        	else
        	{

        	  const links = [];
        	  links["HurricaneElectric"]="https://bgp.he.net/search?commit=Search&search%5Bsearch%5D=";
        	  window.open(links[buttonValue]+userURL);
        	  
            }
}

