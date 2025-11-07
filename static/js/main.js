
function showNotification(message, type) {
  const container = document.querySelector('[data-toast-container]');
  if (!container) return;

  const toast = document.createElement('div');
  toast.classList.add('toast', `toast-${type}`);
  toast.textContent = message;

  if (type === 'error') {
    toast.style.backgroundColor = '#f56565';
  }

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-fade-out');
    toast.addEventListener('animationend', () => {
      toast.remove();
    });
  }, 3000);

  fetch('/notifications/create', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ message }),
  })
  .then(response => response.json())
  .then(data => {
    if (data.created) {
      document.dispatchEvent(new CustomEvent('new-notification'));
    }
  });
}