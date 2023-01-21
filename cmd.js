function displayUpperCase() 
  {
    let textInput = document.getElementById("textInput").value;
    let textOutput = textInput.toUpperCase();
    document.getElementById("textOutput").innerHTML = textOutput;
  }
function identifyIPAddress() 
  {
    var textInput = document.getElementById("textInput").value;
    var Output = textInput;
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
    const ipmatches = textInput.match(ipRegex);
    if (ipmatches && matches.length > 0) {
      ipmatches.forEach(match => {
       Output = Output.replace(match, `<span style="background-color: yellow;">${match}</span>`);
      }); 
    } 
    document.getElementById("textOutput").innerHTML = Output;
  }
