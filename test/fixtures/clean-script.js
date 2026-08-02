// A clean script with no sensitive capabilities
function leftPad(str, len, ch) {
  ch = ch || ' ';
  while (str.length < len) str = ch + str;
  return str;
}

console.log(leftPad('hello', 10));
console.log('Script completed cleanly.');
