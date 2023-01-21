function displayUpperCase() 
  {
    let textInput = document.getElementById("textInput").value;
    let textOutput = textInput.toUpperCase();
    document.getElementById("textOutput").innerHTML = textOutput;
  }
function identifyIPAddress() 
  {
    var textInput = document.getElementById("textInput").value;
    //regular expression to identify IP addresses
    const ipRegEx = /\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    //match all IP addresses from the textInput & store in an array
    const ipMatches = textInput.match(ipRegEx);
    //replace all IP addresses in the textInput with spans of yellow highlighting
    var Output = textInput.replace(ipRegEx, '<span style="background-color:yellow;">$&</span>');
    //return the output text
    document.getElementById("textOutput").innerHTML = Output;
  }