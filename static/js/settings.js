window.showTab = function(tabId) {
  // Hide all tab panels
  document.querySelectorAll('.settings-section').forEach(tab => tab.style.display = 'none');
  // Remove is-active and aria-selected from all tab buttons
  document.querySelectorAll('.settings-tab').forEach(btn => {
    btn.classList.remove('is-active');
    btn.setAttribute('aria-selected', 'false');
  });
  // Show the selected tab panel
  document.getElementById(tabId).style.display = 'block';
  // Add is-active and aria-selected to the clicked tab button
  const activeTab = document.querySelector(`.settings-tab[aria-controls="settings-${tabId}"]`);
  if (activeTab) {
    activeTab.classList.add('is-active');
    activeTab.setAttribute('aria-selected', 'true');
  }
}

document.addEventListener('DOMContentLoaded', function() {
  const notificationMessage = sessionStorage.getItem('notificationMessage');
  const notificationType = sessionStorage.getItem('notificationType');

  if (notificationMessage && notificationType) {
    showNotification(notificationMessage, notificationType);
    sessionStorage.removeItem('notificationMessage');
    sessionStorage.removeItem('notificationType');
  }

  // Edit icon functionality
  document.querySelectorAll('.edit-icon').forEach(icon => {
    icon.addEventListener('click', () => {
      const targetInput = document.getElementById(icon.dataset.target);
      if (targetInput.hasAttribute('readonly')) {
        targetInput.removeAttribute('readonly');
        targetInput.focus();
      } else {
        targetInput.setAttribute('readonly', 'readonly');
      }
    });
  });

  // Modal functionality
  const modal = document.getElementById('profile-picture-modal');
  const profilePictureContainer = document.querySelector('.profile-picture-container');
  const closeButton = document.querySelector('.modal .close');
  let originalImageSrc = '';

  if (profilePictureContainer) {
    profilePictureContainer.addEventListener('click', () => {
      originalImageSrc = document.querySelector('.modal-image').src;
      modal.style.display = 'block';
    });
  }

  if (closeButton) {
    closeButton.addEventListener('click', () => {
      document.querySelector('.modal-image').src = originalImageSrc;
      modal.style.display = 'none';
    });
  }

  window.addEventListener('click', (event) => {
    if (event.target == modal) {
      document.querySelector('.modal-image').src = originalImageSrc;
      modal.style.display = 'none';
    }
  });

  const fileInput = document.getElementById('profile_picture');
  const modalImage = document.querySelector('.modal-image');

  if (fileInput) {
    fileInput.addEventListener('change', function() {
      if (this.files && this.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
          modalImage.src = e.target.result;
        }
        reader.readAsDataURL(this.files[0]);
      }
    });
  }

  const emailInput = document.getElementById('email');
  const otpGroup = document.getElementById('otp-group');
  const getOtpButton = document.getElementById('get-otp-button');
  const originalEmail = emailInput ? emailInput.value : '';

  // Username validation
  const usernameInput = document.getElementById('username');
  const usernameFeedback = document.getElementById('username-feedback');
  const originalUsername = usernameInput ? usernameInput.value : '';

  if (usernameInput) {
    usernameInput.addEventListener('input', () => {
      const newUsername = usernameInput.value;
      if (newUsername !== originalUsername) {
        fetch(`/api/check-username?username=${newUsername}`)
          .then(response => response.json())
          .then(data => {
            const updateProfileButton = document.getElementById('update-profile-button');
            if (data.available) {
              usernameFeedback.innerHTML = '<small style="color: green;">Username is available.</small>';
              updateProfileButton.disabled = false;
            } else {
              let suggestionHtml = '<small style="color: red;">Username is taken.</small>';
              if (data.suggestion) {
                suggestionHtml += ` Did you mean <a href="#" onclick="useSuggestion(event, '${data.suggestion}')">${data.suggestion}</a>?`;
              }
              suggestionHtml += '</small>';
              usernameFeedback.innerHTML = suggestionHtml;
              updateProfileButton.disabled = true;
            }
          });
      } else {
        usernameFeedback.innerHTML = '';
        document.getElementById('update-profile-button').disabled = false;
      }
    });
  }

  window.useSuggestion = function(event, suggestion) {
    event.preventDefault();
    usernameInput.value = suggestion;
    usernameInput.dispatchEvent(new Event('input'));
  }

  if (emailInput) {
    emailInput.addEventListener('input', () => {
      if (emailInput.value !== originalEmail) {
        getOtpButton.style.display = 'block';
        fetch(`/api/check-email?email=${emailInput.value}`)
          .then(response => response.json())
          .then(data => {
            if (data.available) {
              document.getElementById('email-feedback').innerHTML = '<small style="color: green;">Email is available.</small>';
            } else {
              document.getElementById('email-feedback').innerHTML = '<small style="color: red;">Email is already registered.</small>';
            }
          });
      } else {
        getOtpButton.style.display = 'none';
        otpGroup.style.display = 'none';
        document.getElementById('email-feedback').innerHTML = '';
      }
    });
  }

  if (getOtpButton) {
    getOtpButton.addEventListener('click', () => {
      const newEmail = emailInput.value;
      if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(newEmail)) {
        showNotification('Please enter a valid email address.', 'error');
        return;
      }

      // Disable the button to prevent multiple clicks
      getOtpButton.disabled = true;
      getOtpButton.textContent = 'Sending...';

      fetch('/send-email-otp', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email: newEmail }),
        })
        .then(response => {
          if (!response.ok) {
            return response.json().then(err => { throw err; });
          }
          return response.json();
        })
        .then(data => {
          if (data.message) {
            document.getElementById('otp-group').style.display = 'block';
            document.getElementById('update-profile-button').style.display = 'none';
            showNotification(data.message, 'success');
          } else {
            showNotification(data.error || 'Could not send OTP. Please try again later.', 'error');
          }
        })
        .catch((err) => {
          showNotification(err.error || 'An error occurred. Please try again.', 'error');
        })
        .finally(() => {
          // Re-enable the button
          getOtpButton.disabled = false;
          getOtpButton.textContent = 'Get OTP';
        });
    });
  }

  const updateProfileForm = document.getElementById('update-profile-form');
  if (updateProfileForm) {
    updateProfileForm.addEventListener('submit', function(event) {
      event.preventDefault(); // Prevent the default form submission

      const updateProfileButton = document.getElementById('update-profile-button');
      // Add loading state
      updateProfileButton.disabled = true;
      updateProfileButton.textContent = 'Updating...';
      updateProfileButton.classList.add('loading');

      const username = document.getElementById('username').value;
      const email = document.getElementById('email').value;
      const otp = document.getElementById('otp').value;
      const formData = new FormData(updateProfileForm);

      formData.append('update_target', 'profile-details');
      formData.append('username', username);
      formData.append('email', email);
      if (otp) {
        formData.append('otp', otp);
      }

      fetch('/settings', {
          method: 'POST',
          body: formData,
        })
        .then(response => {
          if (response.ok) {
            window.location.reload();
          } else {
            response.json().then(data => {
              showNotification(data.message, 'error');
            });
          }
        })
        .catch(error => {
          console.error('Error:', error);
          showNotification('An unexpected error occurred. Please try again.', 'error');
        })
        .finally(() => {
          // Remove loading state
          updateProfileButton.disabled = false;
          updateProfileButton.textContent = 'Update Profile';
          updateProfileButton.classList.remove('loading');
        });
    });
  }

  const updatePictureForm = document.getElementById('update-picture-form');
  if (updatePictureForm) {
    updatePictureForm.addEventListener('submit', function(event) {
      event.preventDefault();

      const formData = new FormData(updatePictureForm);
      const fileInput = document.getElementById('profile_picture');

      // Check if the remove button was clicked
      const isRemoving = document.activeElement.name === 'remove_profile_picture';

      if (!isRemoving && fileInput.files.length === 0) {
        // No file selected and not removing, so don't do anything.
        return;
      }

      if (isRemoving) {
        formData.append('remove_profile_picture', 'true');
      }

      console.log('Update picture form submitted');

      // Show loading indicator
      const loadingIndicator = document.createElement('div');
      loadingIndicator.className = 'loading-indicator';
      loadingIndicator.textContent = isRemoving ? 'Removing...' : 'Uploading...';
      updatePictureForm.appendChild(loadingIndicator);
      const submitButtons = updatePictureForm.querySelectorAll('button[type="submit"]');
      submitButtons.forEach(button => button.disabled = true);

      fetch(updatePictureForm.action, {
          method: 'POST',
          body: formData,
        })
        .then(response => {
          if (response.ok) {
            return response.json();
          }
          throw new Error('Network response was not ok.');
        })
        .then(data => {
          if (data.status === 'success') {
            window.location.reload();
          } else {
            showNotification(data.message, data.status);
          }
        })
        .catch(error => {
          console.error('Error:', error);
          showNotification('An error occurred while updating the picture.', 'error');
        })
        .finally(() => {
          // Hide loading indicator
          if (loadingIndicator) {
            loadingIndicator.remove();
          }
          submitButtons.forEach(button => button.disabled = false);
        });
    });
  }

  // Password validation
  const passwordInput = document.getElementById("new_password");
  const confirmPasswordInput = document.getElementById("confirm_password");
  const requirementsContainer = document.querySelector(".password-requirements");
  const matchHint = document.getElementById("password-match-hint");

  if (passwordInput && requirementsContainer && confirmPasswordInput && matchHint) {
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

    const setMatchState = (message, state) => {
      matchHint.textContent = message;
      matchHint.classList.remove("is-match", "is-error");
      if (state === "match") {
        matchHint.classList.add("is-match");
      } else if (state === "error") {
        matchHint.classList.add("is-error");
      }
    };

    const evaluateMatch = () => {
      const passwordValue = passwordInput.value;
      const confirmValue = confirmPasswordInput.value;
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
      requirementsContainer.classList.add("is-visible");
      updateRequirements(passwordInput.value);
      evaluateMatch();
    });

    passwordInput.addEventListener("input", (event) => {
      updateRequirements(event.target.value);
      evaluateMatch();
    });

    passwordInput.addEventListener("blur", () => {
      if (!passwordInput.value) {
        requirementsContainer.classList.remove("is-visible");
        requirementItems.forEach((item) => item.classList.remove("requirement-met"));
      }
      evaluateMatch();
    });

    confirmPasswordInput.addEventListener("input", evaluateMatch);
    confirmPasswordInput.addEventListener("focus", evaluateMatch);
    confirmPasswordInput.addEventListener("blur", () => {
      if (!confirmPasswordInput.value) {
        setMatchState("", null);
      }
    });
  }

  const emailNotificationsToggle = document.getElementById('email_notifications');
  if (emailNotificationsToggle) {
    emailNotificationsToggle.addEventListener('change', function() {
      const form = this.closest('form');
      const formData = new FormData(form);
      fetch(form.action, {
          method: 'POST',
          body: formData
        })
        .then(response => response.json())
        .then(data => {
          if (data.status === 'success') {
            // Optionally, show a success message to the user without reloading
            console.log(data.message);
          } else {
            // Handle errors
            console.error('Error updating settings:', data.message);
          }
        })
        .catch(error => console.error('Error:', error));
    });
  }

  const updatePasswordForm = document.getElementById('update-password-form');
  if (updatePasswordForm) {
    updatePasswordForm.addEventListener('submit', function(event) {
      event.preventDefault();
      const formData = new FormData(updatePasswordForm);
      fetch(updatePasswordForm.action, {
          method: 'POST',
          body: formData
        })
        .then(response => response.json())
        .then(data => {
          if (data.status === 'success') {
            window.location.reload();
          } else if (data.status === 'error_same_password') {
            sessionStorage.setItem('notificationMessage', data.message);
            sessionStorage.setItem('notificationType', 'error');
            window.location.reload();
          } else {
            showNotification(data.message, 'error');
            document.dispatchEvent(new CustomEvent('new-notification'));
          }
        })
        .catch(error => {
          console.error('Error:', error);
          showNotification('An unexpected error occurred. Please try again.', 'error');
          document.dispatchEvent(new CustomEvent('new-notification'));
        });
    });
  }
});