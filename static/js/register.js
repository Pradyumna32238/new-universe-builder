
function initializePasswordValidation(context = document) {
    const passwordInput = context.querySelector("#password");
    const confirmInput = context.querySelector("#password_confirm");
    const requirementsContainer = context.querySelector(".password-requirements");
    const matchHint = context.querySelector("#passwordMatchHint");

    if (!passwordInput || !requirementsContainer) {
      return;
    }

    const requirementItems = requirementsContainer.querySelectorAll("[data-rule]");
    const checks = {
      length: (value) => value.length >= 8,
      uppercase: (value) => /[A-Z]/.test(value),
      lowercase: (value) => /[a-z]/.test(value),
      number: (value) => /\d/.test(value),
      special: (value) => /[^A-Za-z0-9]/.test(value),
    };

    const updateRequirements = (value) => {
      requirementItems.forEach((item) => {
        const rule = item.dataset.rule;
        const isMet = checks[rule] ? checks[rule](value) : false;
        item.classList.toggle("requirement-met", isMet);
      });
    };

    const toggleVisibility = (shouldShow) => {
      requirementsContainer.classList.toggle("is-visible", shouldShow);
    };

    const setMatchState = (message, state) => {
      if (!matchHint) {
        return;
      }
      matchHint.textContent = message;
      matchHint.classList.remove("is-match", "is-error");
      if (state === "match") {
        matchHint.classList.add("is-match");
      } else if (state === "error") {
        matchHint.classList.add("is-error");
      }
    };

    const evaluateMatch = () => {
      if (!confirmInput || !matchHint) {
        return;
      }
      const passwordValue = passwordInput.value;
      const confirmValue = confirmInput.value;
      if (!confirmValue) {
        setMatchState("", null);
        return;
      }
      if (passwordValue === confirmValue) {
        setMatchState("Passwords match.", "match");
      } else {
        setMatchState("Passwords do not match yet.", "error");
      }
    };

    passwordInput.addEventListener("focus", () => {
      toggleVisibility(true);
      updateRequirements(passwordInput.value);
      evaluateMatch();
    });

    passwordInput.addEventListener("input", (event) => {
      toggleVisibility(true);
      updateRequirements(event.target.value);
      evaluateMatch();
    });

    passwordInput.addEventListener("blur", () => {
      if (!passwordInput.value) {
        toggleVisibility(false);
        requirementItems.forEach((item) => item.classList.remove("requirement-met"));
      }
      evaluateMatch();
    });

    if (confirmInput) {
      confirmInput.addEventListener("input", evaluateMatch);
      confirmInput.addEventListener("focus", evaluateMatch);
      confirmInput.addEventListener("blur", () => {
        if (!confirmInput.value) {
          setMatchState("", null);
        }
      });
    }

    evaluateMatch();
}

document.addEventListener("DOMContentLoaded", function () {
      const usernameInput = document.getElementById("username");
      const usernameHint = document.getElementById("usernameAvailabilityHint");
      const emailInput = document.getElementById("email");
      const emailHint = document.getElementById("emailAvailabilityHint");

      initializePasswordValidation();

      const debounce = (fn, delay = 250) => {
        let timer;
        return (...args) => {
          clearTimeout(timer);
          timer = setTimeout(() => fn(...args), delay);
        };
      };

      const showUsernameHint = (message, state = null) => {
        if (!usernameHint) {
          return;
        }
        usernameHint.textContent = message;
        usernameHint.classList.remove("is-error", "is-success");
        if (state === "error") {
          usernameHint.classList.add("is-error");
        } else if (state === "success") {
          usernameHint.classList.add("is-success");
        }
      };

      const showEmailHint = (message, state = null) => {
        if (!emailHint) {
          return;
        }
        emailHint.textContent = message;
        emailHint.classList.remove("is-error", "is-success");
        if (state === "error") {
          emailHint.classList.add("is-error");
        } else if (state === "success") {
          emailHint.classList.add("is-success");
        }
      };

      const checkUsernameAvailability = debounce(async (value) => {
        const trimmed = value.trim();
        if (!trimmed) {
          showUsernameHint("", null);
          return;
        }

        if (trimmed.length < 5) {
            showUsernameHint("Username must be at least 5 characters long.", "error");
            return;
        }

        if (!/^[a-zA-Z0-9]+$/.test(trimmed)) {
            showUsernameHint("Username must be alphanumeric.", "error");
            return;
        }

        try {
          const response = await fetch(`/api/check-username?username=${encodeURIComponent(trimmed)}`);
          if (!response.ok) {
            showUsernameHint("Unable to check username right now.", "error");
            return;
          }
          const data = await response.json();
          if (data.available) {
            showUsernameHint("Great choice! This username is available.", "success");
          } else if (data.suggestion) {
            showUsernameHint(`Already taken. Try "${data.suggestion}" instead.`, "error");
          } else {
            showUsernameHint("This username is already taken.", "error");
          }
        } catch (error) {
          showUsernameHint("Unable to check username right now.", "error");
        }
      });

      const checkEmailAvailability = debounce(async (value) => {
        const trimmed = value.trim();
        if (!trimmed) {
          showEmailHint("", null);
          return;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(trimmed)) {
          showEmailHint("Please enter a valid email address.", "error");
          return;
        }

        try {
          const response = await fetch(`/api/check-email?email=${encodeURIComponent(trimmed)}`);
          if (!response.ok) {
            showEmailHint("Unable to check email right now.", "error");
            return;
          }
          const data = await response.json();
          if (data.available) {
            showEmailHint("This email is available.", "success");
          } else {
            showEmailHint("This email is already registered.", "error");
          }
        } catch (error) {
          showEmailHint("Unable to check email right now.", "error");
        }
      });

      if (usernameInput) {
        usernameInput.addEventListener("input", (event) => {
          showUsernameHint("Checking availability...");
          checkUsernameAvailability(event.target.value);
        });
        usernameInput.addEventListener("blur", () => {
          if (!usernameInput.value.trim()) {
            showUsernameHint("", null);
          }
        });
      }

      if (emailInput) {
        emailInput.addEventListener("input", (event) => {
          showEmailHint("Checking availability...");
          checkEmailAvailability(event.target.value);
        });
        emailInput.addEventListener("blur", () => {
          if (!emailInput.value.trim()) {
            showEmailHint("", null);
          }
        });
      }
    });