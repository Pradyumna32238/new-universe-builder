document.addEventListener("DOMContentLoaded", () => {
  const characterCards = document.querySelectorAll(".character-card");

  characterCards.forEach((card) => {
    const details = card.querySelector(".character-edit");
    const summary = card.querySelector("summary");

    summary.addEventListener("click", (event) => {
      event.preventDefault();
      const wasOpen = details.hasAttribute("open");

      // Close all other open details and show their edit buttons
      document.querySelectorAll(".character-edit[open]").forEach((openDetail) => {
        if (openDetail !== details) {
          openDetail.removeAttribute("open");
          openDetail.querySelector("summary").style.display = "block"; // Show the edit button of other cards
        }
      });

      if (!wasOpen) {
        details.setAttribute("open", "");
        summary.style.display = "none"; // Hide the edit button of the current card
      } else {
        details.removeAttribute("open");
        summary.style.display = "block"; // Show the edit button of the current card
      }
    });
  });

  document.body.addEventListener("click", (event) => {
    if (!event.target.closest(".character-edit")) {
      document.querySelectorAll(".character-edit[open]").forEach((openDetail) => {
        openDetail.removeAttribute("open");
        openDetail.querySelector("summary").style.display = "block"; // Show the edit button when clicking outside
      });
    }
  });
});

function showTab(tabId) {
  // Hide all tab panels
  document.querySelectorAll('.tab-content').forEach(tab => tab.style.display = 'none');
  // Remove is-active and aria-selected from all tab buttons
  document.querySelectorAll('.settings-tab').forEach(btn => {
    btn.classList.remove('is-active');
    btn.setAttribute('aria-selected', 'false');
  });
  // Show the selected tab panel
  document.getElementById(tabId).style.display = 'block';
  // Add is-active and aria-selected to the clicked tab button
  const tabButton = document.querySelector(`.settings-tab[aria-controls="universe-${tabId}"]`);
  if (tabButton) {
    tabButton.classList.add('is-active');
    tabButton.setAttribute('aria-selected', 'true');
  }
}