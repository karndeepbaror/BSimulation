// Navigation
const sections = document.querySelectorAll("section");
const navLinks = document.querySelectorAll("nav a");

navLinks.forEach(link => {
  link.addEventListener("click", e => {
    e.preventDefault();
    const id = link.id.replace("Btn", "");
    sections.forEach(sec => sec.classList.remove("active"));
    document.getElementById(id).classList.add("active");
  });
});

// Game logic
const gameArea = document.getElementById("gameArea");
const player = document.getElementById("player");
const scoreText = document.getElementById("score");
let score = 0;
let gameRunning = false;
let poops = [];
let playerX = gameArea.clientWidth / 2 - 20;

// Move player
document.addEventListener("keydown", e => {
  if (e.key === "ArrowLeft") playerX -= 30;
  if (e.key === "ArrowRight") playerX += 30;
  playerX = Math.max(0, Math.min(playerX, gameArea.clientWidth - 40));
  player.style.left = `${playerX}px`;
});

// Start game when Game tab active
document.getElementById("gameBtn").addEventListener("click", startGame);

function startGame() {
  if (gameRunning) return;
  gameRunning = true;
  score = 0;
  scoreText.textContent = "Score: 0";
  poops.forEach(p => p.remove());
  poops = [];
  spawnPoop();
  gameLoop();
}

// Spawn falling poop
function spawnPoop() {
  const poop = document.createElement("div");
  poop.classList.add("poop");
  poop.textContent = "💩";
  poop.style.left = `${Math.random() * (gameArea.clientWidth - 30)}px`;
  poop.style.top = "0px";
  gameArea.appendChild(poop);
  poops.push(poop);

  setTimeout(spawnPoop, 1000 + Math.random() * 800);
}

// Game loop
function gameLoop() {
  poops.forEach((poop, i) => {
    let top = parseFloat(poop.style.top);
    top += 4;
    poop.style.top = `${top}px`;

    // Collision check
    const poopRect = poop.getBoundingClientRect();
    const playerRect = player.getBoundingClientRect();
    if (
      poopRect.bottom > playerRect.top &&
      poopRect.left < playerRect.right &&
      poopRect.right > playerRect.left &&
      poopRect.top < playerRect.bottom
    ) {
      alert("💩 You got hit! Game Over!\nYour score: " + score);
      gameRunning = false;
      poops.forEach(p => p.remove());
      poops = [];
      return;
    }

    // Remove poop if off-screen
    if (top > gameArea.clientHeight) {
      poop.remove();
      poops.splice(i, 1);
      score++;
      scoreText.textContent = `Score: ${score}`;
    }
  });

  if (gameRunning) requestAnimationFrame(gameLoop);
}
