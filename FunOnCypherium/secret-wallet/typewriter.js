const paragraphs = [
  "The longer your salt and passphrase, the better.",
  "Just lock them away in your memory.",
  "Only the unique salt and passphrase you came up with can unlock your wallet."
];

const CHAR_DELAY = 35;
const PARAGRAPH_DELAY = 800; 

let paraIndex = 0;
let charIndex = 0;

const terminal = document.getElementById("terminalText");

function typeWriter() {
  if (!terminal) return;

  if (paraIndex >= paragraphs.length) return;

  const current = paragraphs[paraIndex];

  if (charIndex < current.length) {
    terminal.textContent += current.charAt(charIndex);
    charIndex++;
    setTimeout(typeWriter, CHAR_DELAY);
  } else {
    terminal.textContent += "\n\n";
    paraIndex++;
    charIndex = 0;
    setTimeout(typeWriter, PARAGRAPH_DELAY);
  }
}

window.onload = typeWriter;
