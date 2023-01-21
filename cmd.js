  function identifyIPAddress(textInput) 
  {
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
    const matches = textInput.match(ipRegex);
    if (matches && matches.length > 0) {
      return matches[0];
    } else {
      return 'No IP address found';
    }
  }
