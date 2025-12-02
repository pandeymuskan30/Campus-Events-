document.addEventListener("DOMContentLoaded", () => {
  const nameInput = document.getElementById("search-name");
  const categoryInput = document.getElementById("search-category");
  const dateInput = document.getElementById("search-date");
  const events = document.querySelectorAll(".event-card");

  function filterEvents() {
    const nameVal = nameInput.value.toLowerCase();
    const categoryVal = categoryInput.value.toLowerCase();
    const dateVal = dateInput.value;

    events.forEach(event => {
      const eventName = event.dataset.name;
      const eventCategory = event.dataset.category;
      const eventDate = event.dataset.date;

      let isVisible = true;

      if (nameVal && !eventName.includes(nameVal)) {
        isVisible = false;
      }
      if (categoryVal && eventCategory !== categoryVal) {
        isVisible = false;
      }
      if (dateVal && eventDate !== dateVal) {
        isVisible = false;
      }

      event.style.display = isVisible ? "block" : "none";
    });
  }

  // 🔹 Trigger filtering instantly
  nameInput.addEventListener("input", filterEvents);
  categoryInput.addEventListener("change", filterEvents);
  dateInput.addEventListener("change", filterEvents);
});