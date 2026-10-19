document.addEventListener("DOMContentLoaded", () => {
  const dataNode = document.getElementById("report-page-data");
  if (!dataNode) return;

  const pageData = JSON.parse(dataNode.textContent || "{}");
  const scanId = pageData.scanId;
  const reports = pageData.reports || { general: "", technical: "" };
  let currentProvider = "ollama";

  const providerConfig = {
    ollama: {
      name: "Ollama",
      color: "purple",
      icon: "ph-cube",
      model: "llama3.2",
      available: true,
      reason: "",
    },
    ollama_cloud: {
      name: "Ollama Cloud",
      color: "cyan",
      icon: "ph-cloud",
      model: "",
      available: false,
      reason: "Ollama Cloud API key not configured",
    },
    openai: {
      name: "OpenAI GPT",
      color: "emerald",
      icon: "ph-brain",
      model: "",
      available: false,
      reason: "OpenAI API key not configured",
    },
    gemini: {
      name: "Google Gemini",
      color: "blue",
      icon: "ph-sparkle",
      model: "",
      available: false,
      reason: "Gemini API key not configured",
    },
  };

  const updateAssistantStatus = (text) => {
    const el = document.getElementById("assistant-status");
    if (el) el.textContent = text;
  };

  const escapeHtml = (text) => {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  };

  const applyProviderMetadata = (metadata) => {
    (metadata.providers || []).forEach((provider) => {
      if (!providerConfig[provider.id]) return;
      providerConfig[provider.id] = {
        ...providerConfig[provider.id],
        ...provider,
      };

      const modelLabel = document.getElementById(`model-${provider.id}`);
      if (modelLabel) {
        modelLabel.textContent = provider.available
          ? provider.model
            ? `Model: ${provider.model}`
            : provider.display_name
          : provider.reason || "Unavailable";
      }

      const button = document.getElementById(`provider-btn-${provider.id}`);
      if (button) {
        button.disabled = !provider.available;
        button.classList.toggle("opacity-40", !provider.available);
        button.classList.toggle("cursor-not-allowed", !provider.available);
        button.title = provider.available
          ? provider.model
            ? `${provider.name} • ${provider.model}`
            : provider.name
          : provider.reason || `${provider.name} unavailable`;
      }
    });

    const preferred = metadata.default_provider;
    if (preferred && providerConfig[preferred]?.available) {
      currentProvider = preferred;
      switchProvider(preferred, true);
      updateAssistantStatus(
        `Ask about this scan with ${providerConfig[preferred].name}`,
      );
    } else {
      updateAssistantStatus("Ask about this scan");
    }
  };

  const getMessageContainer = () =>
    document.getElementById(`chat-${currentProvider}`);

  const loadProviderMetadata = async () => {
    try {
      const response = await fetch("/api/chat/providers");
      if (!response.ok) return;
      applyProviderMetadata(await response.json());
    } catch (error) {
      console.error("Failed to load provider metadata:", error);
    }
  };

  const loadChatHistory = async (provider) => {
    const container = document.getElementById(`chat-${provider}`);
    if (!container || !providerConfig[provider]?.available) return;

    try {
      const response = await fetch(`/api/chat/history/${scanId}/${provider}`);
      if (!response.ok) return;
      const history = await response.json();
      const welcome = container.querySelector(".chat-welcome");

      if (!history.length) {
        if (welcome) welcome.style.display = "";
        return;
      }

      if (welcome) welcome.style.display = "none";
      container
        .querySelectorAll(":scope > div:not(.chat-welcome)")
        .forEach((el) => el.remove());

      history.forEach((message) => {
        if (message.role === "user") {
          const userMessage = document.createElement("div");
          userMessage.className = "flex justify-end mb-3";
          userMessage.innerHTML = `<div class="bg-purple-600/30 border border-purple-500/30 rounded-2xl rounded-tr-sm px-4 py-2 max-w-[80%]">
            <p class="text-sm text-gray-200">${escapeHtml(message.content)}</p>
          </div>`;
          container.appendChild(userMessage);
          return;
        }

        const aiMessage = document.createElement("div");
        aiMessage.className = "flex justify-start mb-3";
        aiMessage.innerHTML = `<div class="bg-gray-800/50 border border-gray-700/50 rounded-2xl rounded-tl-sm px-4 py-2 max-w-[85%]">
          <div class="prose prose-sm prose-invert max-w-none text-gray-300">${escapeHtml(message.content).replace(/\n/g, "<br>")}</div>
        </div>`;
        container.appendChild(aiMessage);
      });

      container.scrollTop = container.scrollHeight;
    } catch (error) {
      console.error("Failed to load chat history:", error);
    }
  };

  const switchProvider = (provider, force = false) => {
    if (!force && !providerConfig[provider]?.available) {
      showToast(
        providerConfig[provider]?.reason || `${provider} is unavailable`,
        "warning",
      );
      return;
    }

    currentProvider = provider;
    ["ollama", "ollama_cloud", "openai", "gemini"].forEach((name) => {
      const container = document.getElementById(`chat-${name}`);
      if (!container) return;
      container.classList.toggle("hidden", name !== provider);
    });

    loadChatHistory(provider);
    const activeProvider = providerConfig[provider];
    if (activeProvider) {
      updateAssistantStatus(
        `Ask about this scan with ${activeProvider.name}${activeProvider.model ? ` • ${activeProvider.model}` : ""}`,
      );
    }
  };

  const clearCurrentProviderHistory = async () => {
    if (!providerConfig[currentProvider]?.available) return;
    if (!confirm(`Clear ${providerConfig[currentProvider].name} chat history?`)) {
      return;
    }

    try {
      await fetch(`/api/chat/history/${scanId}/${currentProvider}`, {
        method: "DELETE",
      });
      const container = getMessageContainer();
      if (container) {
        container
          .querySelectorAll(":scope > div:not(.chat-welcome)")
          .forEach((el) => el.remove());
        const welcome = container.querySelector(".chat-welcome");
        if (welcome) welcome.style.display = "";
      }
    } catch (error) {
      console.error("Failed to clear chat history:", error);
    }
  };

  const sendMessage = async (event) => {
    event.preventDefault();

    const input = document.getElementById("chat-input");
    const sendBtn = document.getElementById("chat-send-btn");
    const container = getMessageContainer();
    const message = input?.value.trim();

    if (!message || !container) return;
    if (!providerConfig[currentProvider]?.available) {
      showToast(
        providerConfig[currentProvider]?.reason ||
          "Selected provider is unavailable",
        "warning",
      );
      return;
    }

    const welcome = container.querySelector(".chat-welcome");
    if (welcome) welcome.style.display = "none";

    input.disabled = true;
    sendBtn.disabled = true;

    const config = providerConfig[currentProvider];
    container.insertAdjacentHTML(
      "beforeend",
      `<div class="flex justify-end">
        <div class="max-w-[80%] bg-purple-500/20 border border-purple-500/30 rounded-xl rounded-tr-sm px-3 py-2">
          <p class="text-white text-sm">${escapeHtml(message)}</p>
        </div>
      </div>`,
    );

    const loadingId = `loading-${Date.now()}`;
    container.insertAdjacentHTML(
      "beforeend",
      `<div id="${loadingId}" class="flex items-start gap-2">
        <div class="w-7 h-7 bg-purple-500/20 rounded-lg flex-shrink-0 flex items-center justify-center">
          <i class="ph-fill ph-robot text-purple-400 text-sm animate-pulse"></i>
        </div>
        <div class="bg-slate-800/50 rounded-xl rounded-tl-sm px-3 py-2">
          <div class="flex items-center gap-2">
            <div class="flex gap-1">
              <span class="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce" style="animation-delay: 0ms"></span>
              <span class="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce" style="animation-delay: 150ms"></span>
              <span class="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce" style="animation-delay: 300ms"></span>
            </div>
            <span class="text-slate-400 text-xs loading-timer">Thinking...</span>
          </div>
        </div>
      </div>`,
    );
    container.scrollTop = container.scrollHeight;

    let seconds = 0;
    const timerInterval = window.setInterval(() => {
      seconds += 1;
      const timerSpan = document
        .getElementById(loadingId)
        ?.querySelector(".loading-timer");
      if (timerSpan) {
        timerSpan.textContent = `Thinking... ${seconds}s`;
      }
    }, 1000);

    input.value = "";
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 90000);

    try {
      const formData = new FormData();
      formData.append("scan_id", scanId);
      formData.append("message", message);
      formData.append("provider", currentProvider);

      const response = await fetch("/api/chat", {
        method: "POST",
        body: formData,
        signal: controller.signal,
      });
      const responseHtml = await response.text();

      window.clearTimeout(timeoutId);
      window.clearInterval(timerInterval);
      document.getElementById(loadingId)?.remove();

      if (!response.ok || responseHtml.includes("text-red")) {
        container.insertAdjacentHTML(
          "beforeend",
          `<div class="flex items-start gap-2">
            <div class="w-7 h-7 bg-red-500/20 rounded-lg flex-shrink-0 flex items-center justify-center">
              <i class="ph-fill ph-warning text-red-400 text-sm"></i>
            </div>
            <div class="bg-red-500/10 border border-red-500/20 rounded-xl rounded-tl-sm px-3 py-2 max-w-[80%]">
              <div class="text-red-400 text-sm">${responseHtml}</div>
            </div>
          </div>`,
        );
      } else {
        const msgId = `msg-${Date.now()}`;
        container.insertAdjacentHTML(
          "beforeend",
          `<div id="${msgId}" class="flex items-start gap-2">
            <div class="w-7 h-7 bg-purple-500/20 rounded-lg flex-shrink-0 flex items-center justify-center">
              <i class="ph-fill ph-robot text-purple-400 text-sm"></i>
            </div>
            <div class="bg-slate-800/50 border border-slate-700/50 rounded-xl rounded-tl-sm px-3 py-2 max-w-[80%] group">
              <div class="flex items-center justify-between gap-2 mb-1">
                <span class="text-[10px] text-purple-400 font-medium">${config.name}</span>
                <button onclick="copyMessage('${msgId}')" class="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-white transition-opacity" title="Copy">
                  <i class="ph ph-copy text-xs"></i>
                </button>
              </div>
              <div class="text-slate-200 text-sm ai-content">${responseHtml}</div>
            </div>
          </div>`,
        );
      }
    } catch (error) {
      window.clearTimeout(timeoutId);
      window.clearInterval(timerInterval);
      document.getElementById(loadingId)?.remove();
      console.error("Chat error:", error);

      let errorMessage = "Connection error. Please try again.";
      if (error.name === "AbortError") {
        errorMessage =
          "Request timed out. The AI service may be slow or unavailable.";
      } else if (
        error.message?.includes("NetworkError") ||
        error.message?.includes("Failed to fetch")
      ) {
        errorMessage = "Network error. Check your connection and try again.";
      }

      container.insertAdjacentHTML(
        "beforeend",
        `<div class="flex items-start gap-2">
          <div class="w-7 h-7 bg-red-500/20 rounded-lg flex-shrink-0 flex items-center justify-center">
            <i class="ph-fill ph-warning text-red-400 text-sm"></i>
          </div>
          <div class="bg-red-500/10 border border-red-500/20 rounded-xl rounded-tl-sm px-3 py-2 max-w-[80%]">
            <p class="text-red-400 text-sm">${errorMessage}</p>
          </div>
        </div>`,
      );
    }

    input.disabled = false;
    sendBtn.disabled = false;
    input.focus();
    container.scrollTop = container.scrollHeight;
  };

  const copyMessage = async (messageId) => {
    const el = document.getElementById(messageId);
    const content = el?.querySelector(".ai-content");
    if (!content) return;
    try {
      await navigator.clipboard.writeText(content.innerText);
      const icon = el.querySelector("button i");
      if (icon) {
        icon.className = "ph ph-check text-xs text-emerald-400";
        window.setTimeout(() => {
          icon.className = "ph ph-copy text-xs";
        }, 1500);
      }
    } catch (error) {
      console.error("Copy failed:", error);
    }
  };

  window.askQuestion = (question) => {
    const input = document.getElementById("chat-input");
    if (!input) return;
    input.value = question;
    sendMessage(new Event("submit"));
  };

  window.sendMessage = sendMessage;
  window.switchProvider = switchProvider;
  window.clearCurrentProviderHistory = clearCurrentProviderHistory;
  window.copyMessage = copyMessage;
  window.showReport = (type) => {
    const content =
      type === "general" ? reports.general || "" : reports.technical || "";
    const modal = document.getElementById("reportModal");
    const modalContent = document.getElementById("modalContent");
    if (modalContent) modalContent.innerText = content;
    if (modal) modal.style.display = "block";
  };
  window.closeReport = () => {
    const modal = document.getElementById("reportModal");
    if (modal) modal.style.display = "none";
  };

  loadProviderMetadata();
  loadChatHistory("ollama");
});
