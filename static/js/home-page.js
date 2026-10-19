document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("urlInput");
  const clearBtn = document.getElementById("clearBtn");
  const submitBtn = document.getElementById("scanBtn");
  const statusIcon = document.getElementById("inputStatusIcon");
  const errorMessage = document.getElementById("urlErrorMessage");
  const errorText = document.getElementById("urlErrorText");
  const form = document.getElementById("url-form");
  const typing = document.getElementById("typing-text");

  if (input) {
    window.setTimeout(() => input.focus(), 350);

    const updateClearButton = () => {
      if (clearBtn) {
        clearBtn.classList.toggle("hidden", input.value.trim().length === 0);
      }
    };

    const setState = (state) => {
      const wrapper = input.closest(".search-input-wrapper");
      if (!wrapper) return;
      wrapper.classList.remove("valid", "invalid");

      if (state === "valid") {
        wrapper.classList.add("valid");
        if (statusIcon) {
          statusIcon.className =
            "ph-fill ph-check-circle text-3xl transition-all duration-300";
          statusIcon.style.color = "#10b981";
        }
        if (submitBtn) submitBtn.disabled = false;
        errorMessage?.classList.add("hidden");
        return;
      }

      if (state === "invalid") {
        wrapper.classList.add("invalid");
        if (statusIcon) {
          statusIcon.className =
            "ph-fill ph-warning-octagon text-3xl transition-all duration-300";
          statusIcon.style.color = "#f97316";
        }
        if (submitBtn) submitBtn.disabled = true;
        return;
      }

      if (statusIcon) {
        statusIcon.className = "ph ph-link text-3xl";
        statusIcon.style.color = "";
      }
      if (submitBtn) submitBtn.disabled = false;
      errorMessage?.classList.add("hidden");
    };

    const isValidTarget = (value) => {
      if (!value) return false;
      try {
        const candidate = value.includes("://") ? value : `https://${value}`;
        const parsed = new URL(candidate);
        return Boolean(parsed.hostname && parsed.hostname.includes("."));
      } catch {
        return false;
      }
    };

    input.addEventListener("input", () => {
      const value = input.value.trim();
      updateClearButton();

      if (!value) {
        setState("idle");
        return;
      }

      setState(isValidTarget(value) ? "valid" : "invalid");
    });

    form?.addEventListener("submit", (event) => {
      const value = input.value.trim();
      if (!isValidTarget(value)) {
        event.preventDefault();
        setState("invalid");
        if (errorMessage && errorText) {
          errorText.textContent = value
            ? "Please enter a valid URL or domain."
            : "Please enter a URL to analyze.";
          errorMessage.classList.remove("hidden");
        }
        input.focus();
        return;
      }
      showLoader();
    });

    updateClearButton();
  }

  if (typing) {
    const fullText = typing.dataset.text || typing.textContent || "";
    if (!typing.dataset.animated) {
      typing.dataset.animated = "true";
      typing.textContent = "";

      let index = 0;
      const typeNextCharacter = () => {
        if (index >= fullText.length) {
          typing.textContent = fullText;
          return;
        }

        typing.textContent += fullText.charAt(index);
        index += 1;
        window.setTimeout(typeNextCharacter, 32);
      };

      window.setTimeout(typeNextCharacter, 180);
    }
  }
});
