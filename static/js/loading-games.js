(() => {
  function initLoadingGames() {
    if (!document.getElementById("gamePanel_ttt")) return;

    let activeGame = "ttt";
    let tttBoard = Array(9).fill("");
    let tttGameOver = false;
    let tttPlayerScore = 0;
    let tttAiScore = 0;
    const WINNING_COMBOS = [
      [0, 1, 2],
      [3, 4, 5],
      [6, 7, 8],
      [0, 3, 6],
      [1, 4, 7],
      [2, 5, 8],
      [0, 4, 8],
      [2, 4, 6],
    ];

    const snakeCanvas = document.getElementById("snakeCanvas");
    const snakeCtx = snakeCanvas?.getContext("2d");
    const SN_GRID = 15;
    const SN_SIZE = snakeCanvas ? snakeCanvas.width / SN_GRID : 0;
    let snakeBody = [];
    let snakeDir = { x: 1, y: 0 };
    let snakeFood = { x: 0, y: 0 };
    let snakeAlive = false;
    let snakeInterval = null;
    let snakeScore = 0;
    let snakeHighScore = 0;
    let snakeSpeed = 150;

    const MEM_ICONS = [
      { icon: "ph-fill ph-shield-check", color: "#60a5fa" },
      { icon: "ph-fill ph-lock-key", color: "#a78bfa" },
      { icon: "ph-fill ph-key", color: "#fbbf24" },
      { icon: "ph-fill ph-fingerprint", color: "#34d399" },
      { icon: "ph-fill ph-eye", color: "#f87171" },
      { icon: "ph-fill ph-bug", color: "#fb923c" },
      { icon: "ph-fill ph-warning", color: "#facc15" },
      { icon: "ph-fill ph-virus", color: "#c084fc" },
    ];
    let memCards = [];
    let memFlipped = [];
    let memMatched = 0;
    let memMoves = 0;
    let memLocked = false;
    let memBestScore = Infinity;

    const switchGame = (id) => {
      document
        .querySelectorAll(".game-panel")
        .forEach((panel) => panel.classList.add("hidden"));
      document
        .querySelectorAll(".game-tab")
        .forEach((tab) => tab.classList.remove("game-tab-active"));
      document.getElementById(`gamePanel_${id}`)?.classList.remove("hidden");
      document.getElementById(`tab${id.charAt(0).toUpperCase()}${id.slice(1)}`)?.classList.add("game-tab-active");
      activeGame = id;
      if (id === "snake") {
        snakeCanvas?.focus();
      }
    };

    const updateScores = () => {
      document.getElementById("tttPlayerScore").textContent = tttPlayerScore;
      document.getElementById("tttAiScore").textContent = tttAiScore;
    };

    const setStatus = (text, colorClass) => {
      const el = document.getElementById("tttStatus");
      el.textContent = text;
      el.className = `text-sm font-semibold mb-4 ${colorClass}`;
    };

    const disableBoard = (disabled) => {
      for (let i = 0; i < 9; i += 1) {
        const cell = document.getElementById(`c${i}`);
        if (!tttBoard[i] && cell) {
          cell.disabled = disabled;
        }
      }
    };

    const highlightWinner = (combo) => {
      combo.forEach((index) =>
        document.getElementById(`c${index}`)?.classList.add("winner-cell"),
      );
    };

    const checkWinner = () => {
      for (const combo of WINNING_COMBOS) {
        const [a, b, c] = combo;
        if (tttBoard[a] && tttBoard[a] === tttBoard[b] && tttBoard[a] === tttBoard[c]) {
          return { mark: tttBoard[a], combo };
        }
      }
      return null;
    };

    const findBestMove = (mark) => {
      for (const combo of WINNING_COMBOS) {
        const values = combo.map((index) => tttBoard[index]);
        if (values.filter((value) => value === mark).length === 2 && values.includes("")) {
          return combo[values.indexOf("")];
        }
      }
      return -1;
    };

    const placeMove = (index, mark) => {
      tttBoard[index] = mark;
      const cell = document.getElementById(`c${index}`);
      cell.textContent = mark;
      cell.classList.add(mark === "X" ? "x-mark" : "o-mark");
      cell.disabled = true;

      const winner = checkWinner();
      if (winner) {
        tttGameOver = true;
        highlightWinner(winner.combo);
        if (winner.mark === "X") {
          tttPlayerScore += 1;
          setStatus("You win!", "text-emerald-400");
        } else {
          tttAiScore += 1;
          setStatus("AI wins!", "text-red-400");
        }
        updateScores();
        disableBoard(true);
        return;
      }

      if (tttBoard.every((cellValue) => cellValue)) {
        tttGameOver = true;
        setStatus("It's a draw!", "text-yellow-400");
        disableBoard(true);
        return;
      }

      setStatus(mark === "X" ? "AI is thinking..." : "Your turn (X)", mark === "X" ? "text-fuchsia-300" : "text-sky-300");
    };

    const aiMove = () => {
      if (tttGameOver) return;
      let move = findBestMove("O");
      if (move === -1) move = findBestMove("X");
      if (move === -1 && !tttBoard[4]) move = 4;
      if (move === -1) {
        const corners = [0, 2, 6, 8].filter((index) => !tttBoard[index]);
        if (corners.length) {
          move = corners[Math.floor(Math.random() * corners.length)];
        }
      }
      if (move === -1) {
        const empty = tttBoard.map((value, index) => (value ? -1 : index)).filter((index) => index !== -1);
        move = empty[Math.floor(Math.random() * empty.length)];
      }
      placeMove(move, "O");
    };

    const handleCellClick = (index) => {
      if (tttBoard[index] || tttGameOver) return;
      placeMove(index, "X");
      if (tttGameOver) return;
      disableBoard(true);
      window.setTimeout(() => {
        aiMove();
        disableBoard(false);
      }, 300);
    };

    const resetGame = () => {
      tttBoard = Array(9).fill("");
      tttGameOver = false;
      for (let i = 0; i < 9; i += 1) {
        const cell = document.getElementById(`c${i}`);
        cell.textContent = "";
        cell.disabled = false;
        cell.className = "ttt-cell";
      }
      setStatus("Your turn (X)", "text-sky-300");
    };

    const drawSnakeBoard = () => {
      if (!snakeCtx || !snakeCanvas) return;
      snakeCtx.fillStyle = "rgba(15, 23, 42, 0.95)";
      snakeCtx.fillRect(0, 0, snakeCanvas.width, snakeCanvas.height);
      snakeCtx.strokeStyle = "rgba(51, 65, 85, 0.3)";
      snakeCtx.lineWidth = 0.5;
      for (let i = 0; i <= SN_GRID; i += 1) {
        snakeCtx.beginPath();
        snakeCtx.moveTo(i * SN_SIZE, 0);
        snakeCtx.lineTo(i * SN_SIZE, snakeCanvas.height);
        snakeCtx.stroke();
        snakeCtx.beginPath();
        snakeCtx.moveTo(0, i * SN_SIZE);
        snakeCtx.lineTo(snakeCanvas.width, i * SN_SIZE);
        snakeCtx.stroke();
      }
    };

    const drawSnake = () => {
      if (!snakeCtx) return;
      snakeBody.forEach((segment, index) => {
        snakeCtx.shadowColor =
          index === 0 ? "rgba(96, 165, 250, 0.5)" : "rgba(96, 165, 250, 0.15)";
        snakeCtx.shadowBlur = index === 0 ? 8 : 3;
        snakeCtx.fillStyle =
          index === 0 ? "rgb(96, 165, 250)" : `rgba(96, 165, 250, ${0.8 - index * 0.03})`;
        snakeCtx.beginPath();
        snakeCtx.roundRect(
          segment.x * SN_SIZE + 1,
          segment.y * SN_SIZE + 1,
          SN_SIZE - 2,
          SN_SIZE - 2,
          3,
        );
        snakeCtx.fill();
        snakeCtx.shadowBlur = 0;
      });
    };

    const drawFood = () => {
      if (!snakeCtx) return;
      const cx = snakeFood.x * SN_SIZE + SN_SIZE / 2;
      const cy = snakeFood.y * SN_SIZE + SN_SIZE / 2;
      snakeCtx.shadowColor = "rgba(192, 132, 252, 0.7)";
      snakeCtx.shadowBlur = 10;
      snakeCtx.fillStyle = "rgb(192, 132, 252)";
      snakeCtx.beginPath();
      snakeCtx.arc(cx, cy, SN_SIZE / 2.8, 0, Math.PI * 2);
      snakeCtx.fill();
      snakeCtx.shadowBlur = 0;
      snakeCtx.fillStyle = "rgba(255,255,255,0.6)";
      snakeCtx.beginPath();
      snakeCtx.arc(cx - 2, cy - 2, 2, 0, Math.PI * 2);
      snakeCtx.fill();
    };

    const spawnFood = () => {
      let position = { x: 0, y: 0 };
      do {
        position = {
          x: Math.floor(Math.random() * SN_GRID),
          y: Math.floor(Math.random() * SN_GRID),
        };
      } while (snakeBody.some((segment) => segment.x === position.x && segment.y === position.y));
      snakeFood = position;
    };

    const endSnake = () => {
      if (!snakeCtx || !snakeCanvas) return;
      snakeAlive = false;
      window.clearInterval(snakeInterval);
      document.getElementById("snakeStatus").textContent = `Game Over! Score: ${snakeScore}`;
      document.getElementById("snakeStatus").className = "text-sm font-semibold text-red-400";
      document.getElementById("snakeStartBtn").querySelector("span").textContent = "Restart";
      snakeCtx.fillStyle = "rgba(0,0,0,0.6)";
      snakeCtx.fillRect(0, 0, snakeCanvas.width, snakeCanvas.height);
      snakeCtx.fillStyle = "#ef4444";
      snakeCtx.font = "bold 18px sans-serif";
      snakeCtx.textAlign = "center";
      snakeCtx.fillText("Game Over", snakeCanvas.width / 2, snakeCanvas.height / 2 - 10);
      snakeCtx.fillStyle = "#94a3b8";
      snakeCtx.font = "13px sans-serif";
      snakeCtx.fillText(`Score: ${snakeScore}`, snakeCanvas.width / 2, snakeCanvas.height / 2 + 14);
    };

    const snakeTick = () => {
      if (!snakeAlive) return;
      const head = { x: snakeBody[0].x + snakeDir.x, y: snakeBody[0].y + snakeDir.y };
      if (
        head.x < 0 ||
        head.x >= SN_GRID ||
        head.y < 0 ||
        head.y >= SN_GRID ||
        snakeBody.some((segment) => segment.x === head.x && segment.y === head.y)
      ) {
        endSnake();
        return;
      }

      snakeBody.unshift(head);
      if (head.x === snakeFood.x && head.y === snakeFood.y) {
        snakeScore += 1;
        document.getElementById("snakeScore").textContent = snakeScore;
        if (snakeScore > snakeHighScore) {
          snakeHighScore = snakeScore;
          document.getElementById("snakeHigh").textContent = snakeHighScore;
        }
        spawnFood();
        if (snakeScore % 5 === 0 && snakeSpeed > 70) {
          snakeSpeed -= 15;
          window.clearInterval(snakeInterval);
          snakeInterval = window.setInterval(snakeTick, snakeSpeed);
        }
        document.getElementById("snakeStatus").textContent = `Score: ${snakeScore} — Keep going!`;
      } else {
        snakeBody.pop();
      }

      drawSnakeBoard();
      drawFood();
      drawSnake();
    };

    const startSnake = () => {
      snakeBody = [
        { x: 7, y: 7 },
        { x: 6, y: 7 },
        { x: 5, y: 7 },
      ];
      snakeDir = { x: 1, y: 0 };
      snakeScore = 0;
      snakeAlive = true;
      snakeSpeed = 150;
      document.getElementById("snakeScore").textContent = "0";
      document.getElementById("snakeStatus").textContent = "Use arrow keys to move";
      document.getElementById("snakeStatus").className = "text-sm font-semibold text-emerald-400";
      document.getElementById("snakeStartBtn").querySelector("span").textContent = "Restart";
      spawnFood();
      window.clearInterval(snakeInterval);
      snakeInterval = window.setInterval(snakeTick, snakeSpeed);
      drawSnakeBoard();
      drawFood();
      drawSnake();
    };

    document.addEventListener("keydown", (event) => {
      if (activeGame !== "snake" || !snakeAlive) return;
      const keyMap = {
        ArrowUp: { x: 0, y: -1 },
        ArrowDown: { x: 0, y: 1 },
        ArrowLeft: { x: -1, y: 0 },
        ArrowRight: { x: 1, y: 0 },
        w: { x: 0, y: -1 },
        s: { x: 0, y: 1 },
        a: { x: -1, y: 0 },
        d: { x: 1, y: 0 },
        W: { x: 0, y: -1 },
        S: { x: 0, y: 1 },
        A: { x: -1, y: 0 },
        D: { x: 1, y: 0 },
      };
      const direction = keyMap[event.key];
      if (direction && !(direction.x === -snakeDir.x && direction.y === -snakeDir.y)) {
        snakeDir = direction;
        event.preventDefault();
      }
    });

    const createMemoryBoard = () => {
      const grid = document.getElementById("memoryGrid");
      grid.innerHTML = "";
      const deck = [...MEM_ICONS, ...MEM_ICONS].map((item, index) => ({ ...item, id: index }));
      for (let i = deck.length - 1; i > 0; i -= 1) {
        const swapIndex = Math.floor(Math.random() * (i + 1));
        [deck[i], deck[swapIndex]] = [deck[swapIndex], deck[i]];
      }
      memCards = deck;
      deck.forEach((card, index) => {
        const el = document.createElement("div");
        el.className = "mem-card";
        el.dataset.idx = index;
        el.innerHTML = `
          <div class="mem-card-inner">
            <div class="mem-card-front"><i class="ph ph-question text-xl"></i></div>
            <div class="mem-card-back"><i class="${card.icon}" style="color:${card.color}"></i></div>
          </div>`;
        el.addEventListener("click", () => flipCard(index, el));
        grid.appendChild(el);
      });
    };

    const flipCard = (index, el) => {
      if (memLocked || el.classList.contains("flipped") || el.classList.contains("matched")) {
        return;
      }
      el.classList.add("flipped");
      memFlipped.push({ index, el, icon: memCards[index].icon });
      if (memFlipped.length !== 2) return;

      memMoves += 1;
      document.getElementById("memoryMoves").textContent = memMoves;
      memLocked = true;
      const [first, second] = memFlipped;
      if (first.icon === second.icon) {
        window.setTimeout(() => {
          first.el.classList.add("matched");
          second.el.classList.add("matched");
          memMatched += 1;
          document.getElementById("memoryMatched").textContent = memMatched;
          if (memMatched === 8) {
            document.getElementById("memoryStatus").textContent = `You won in ${memMoves} moves!`;
            document.getElementById("memoryStatus").className = "text-sm font-semibold text-emerald-400";
            if (memMoves < memBestScore) {
              memBestScore = memMoves;
              document.getElementById("memoryBest").textContent = memBestScore;
            }
          }
          memFlipped = [];
          memLocked = false;
        }, 400);
        return;
      }

      first.el.classList.add("mismatched");
      second.el.classList.add("mismatched");
      window.setTimeout(() => {
        first.el.classList.remove("flipped", "mismatched");
        second.el.classList.remove("flipped", "mismatched");
        memFlipped = [];
        memLocked = false;
      }, 800);
    };

    const resetMemory = () => {
      memFlipped = [];
      memMatched = 0;
      memMoves = 0;
      memLocked = false;
      document.getElementById("memoryMoves").textContent = "0";
      document.getElementById("memoryMatched").textContent = "0";
      document.getElementById("memoryStatus").textContent = "Find all matching pairs!";
      document.getElementById("memoryStatus").className = "text-sm font-semibold text-amber-400";
      createMemoryBoard();
    };

    drawSnakeBoard();
    if (snakeCtx && snakeCanvas) {
      snakeCtx.fillStyle = "#64748b";
      snakeCtx.font = "14px sans-serif";
      snakeCtx.textAlign = "center";
      snakeCtx.fillText("Press Start to play", snakeCanvas.width / 2, snakeCanvas.height / 2);
    }
    createMemoryBoard();

    window.switchGame = switchGame;
    window.handleCellClick = handleCellClick;
    window.resetGame = resetGame;
    window.startSnake = startSnake;
    window.resetMemory = resetMemory;
  }

  document.addEventListener("DOMContentLoaded", initLoadingGames);
})();
