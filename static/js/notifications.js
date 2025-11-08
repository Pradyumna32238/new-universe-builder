
document.addEventListener('DOMContentLoaded', () => {
    const notificationIcon = document.querySelector('[data-notification-toggle]');
    const notificationPanel = document.querySelector('[data-notification-panel]');
    const notificationList = document.querySelector('[data-notification-list]');
    const notificationBadge = document.querySelector('.notification-badge');
    const clearButton = document.querySelector('[data-notification-clear]');

    if (!notificationIcon || !notificationPanel || !notificationList || !clearButton) {
        return;
    }

    const clearNotifications = async () => {
        try {
            const response = await fetch('/notifications/clear', { method: 'POST' });
            if (response.ok) {
                notificationList.innerHTML = '<p class="notification-panel__empty">You have no new notifications.</p>';
                updateBadge(0);
            }
        } catch (error) {
            console.error('Error clearing notifications:', error);
        }
    };

    clearButton.addEventListener('click', clearNotifications);

    const fetchNotifications = async () => {
        try {
            const response = await fetch('/notifications');
            if (response.ok) {
                const notifications = await response.json();
                notificationList.innerHTML = '';
                if (notifications.length === 0) {
                    notificationList.innerHTML = '<p class="notification-panel__empty">You have no new notifications.</p>';
                } else {
                    const recentNotifications = notifications.slice(0, 3);
                    recentNotifications.forEach(notif => {
                        const item = document.createElement('div');
                        item.className = 'notification-item';
                        item.innerHTML = `<p class="notification-message">${notif.message}</p>`;
                        notificationList.appendChild(item);
                    });
                    updateBadge(recentNotifications.length);
                }
            }
        } catch (error) {
            console.error('Error fetching notifications:', error);
        }
    };



    const updateBadge = (count) => {
        if (count > 0) {
            notificationBadge.style.display = 'block';
        } else if (count === 0) {
            notificationBadge.style.display = 'none';
        }
    };

    notificationIcon.addEventListener('click', () => {
        notificationPanel.classList.toggle('hidden');
        if (!notificationPanel.classList.contains('hidden')) {
            fetchNotifications();
        }
    });

    document.addEventListener('click', (event) => {
        if (!notificationPanel.contains(event.target) && !notificationIcon.contains(event.target)) {
            notificationPanel.classList.add('hidden');
        }
    });

    document.addEventListener('new-notification', () => {
        fetchNotifications();
    });

    fetchNotifications();
});