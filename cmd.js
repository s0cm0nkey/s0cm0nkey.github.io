 /*
Implement a small web app that runs basic text analytics on user submitted text. We 
provide initial HTML and CSS files, and you'll be responsible for adding CSS classes 
to the HTML for your JavaScript code to hook into, and for writing JavaScript code 
that computes and displays 4 metrics:
-Total word count of the submitted text
-Unique word count of the submitted text
-Average word length in characters of the submitted text
-Average sentence length in characters of the submitted text.
-The program should print each of these metrics in the appropriate area in the results section.
You'll need to write JavaScript code that achieves the objectives listed above. 
That will require you to add some CSS classes for hooking your jQuery event listeners 
(and to that end, we recommend you follow the convention of prefixing these class names 
with js- to preserve the separation of your application logic from the presentation layer).
*/

- Trigger analysis and results when button is clicked

- calculate total word count of submitted text
	- get text from form 
	- count words // How do I identify words in strings?
	- return number
- calculate unique word count of submitted text
	- get text from form 
	- // Not sure
	- return number
- calculate average word length in characters of submitted text
	- get text from form 
	- count word length in characters
	- add word length totals and divide by amount of words
	- return average length (number)
- calculate average sentence length in characters of submitted text
	- get text from form 
	- count characters between "."
	- add sentence totals and divide by total amount of sentences
	- return average length (number)
- print results in the specified area:
	- show hidden



// Word Count:
function wordCount() {
	$()
}


// Unique Word Count:
function unique() {
	$()
}

/*
function mostFrequentWord(words) {
  var wordFrequencies = {};
  for (var i = 0; i <= words.length; i++) {
    if (words[i] in wordFrequencies) {
      wordFrequencies[words[i]]++;
    }
    else {
      wordFrequencies[words[i]]=1;
    }
  }
  var currentMaxKey = Object.keys(wordFrequencies)[0];
  var currentMaxCount = wordFrequencies[currentMaxKey];
  
  for (var word in wordFrequencies) {
    if (wordFrequencies[word] > currentMaxCount) {
      currentMaxKey = word;
      currentMaxCount = wordFrequencies[word];
    }
  }
  return currentMaxKey;
}
*/


// Average Character length:
function average() {
	$()
}

/*
function average(numbers) {
  var total = numbers[0];
  for (i = 0; i < numbers.length; i++) { 
    total += numbers[i];
  }                      
  return total/numbers.length;
}
*/


// Average Sentence length:
function sentence() {
	$()
}


$(document).ready(function() {
	$('button').on('submit', function() {
		

	});
});