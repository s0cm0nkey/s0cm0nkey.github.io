function displayUpperCase() 
  {
    let textInput = document.getElementById("textInput").value;
    let textOutput = textInput.toUpperCase();
    document.getElementById("textOutput").innerHTML = textOutput;
  }
  function identifyIPAddress() 
  {
    var textInput = document.getElementById("textInput").value;
    var textOutput = textInput;
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
    const matches = textInput.match(ipRegex);
    if (matches && matches.length > 0) {
       textOutput = matches[0];
    } else {
      textOutput =  'No IP address found';
    }
    document.getElementById("textOutput").innerHTML = textOutput;
  }
