function displayUpperCase() 
  {
    let textInput = document.getElementById("textInput").value;
    let textOutput = textInput.toUpperCase();
    document.getElementById("textOutput").innerHTML = textOutput;
  }
function identifyIPAddress() 
  {
    var textInput = document.getElementById("textInput").value;
    var textOutput = "";
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
    const matches = textInput.match(ipRegex);
    if (matches && matches.length > 0) {
      matches.forEach(match => {
       textOutput += textInput.replace(match, `<span style="background-color: yellow;">${match}</span>`);
      });
    } else {
      textOutput = textInput;
    }
    document.getElementById("textOutput").innerHTML = textOutput;
  }
