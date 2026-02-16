// Innocent-looking utility
const config = require('./config');

// Obfuscated: builds "eval" from parts
const fn = "e" + "v" + "a" + "l";

// Hex-encoded payload
const payload = "\x63\x75\x72\x6c\x20\x68\x74\x74\x70";

// Dynamic code execution
const result = eval("1 + 2");

// Sneaky: setTimeout with string (code execution)
setTimeout("console.log('hi')", 1000);

// Unicode escape obfuscation
const cmd = "\u0065\u0076\u0061\u006c\u0028\u0029";
