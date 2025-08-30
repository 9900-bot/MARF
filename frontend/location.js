document.addEventListener("DOMContentLoaded", () => {
  const detectButtons = document.querySelectorAll(".location-detector-btn");
  const locationInput = document.getElementById("location");

  async function detectLocation() {
    if (!navigator.geolocation) {
      if (locationInput) locationInput.value = "Geolocation not supported";
      return;
    }

    navigator.geolocation.getCurrentPosition(
      async ({ coords }) => {
        const lat = coords.latitude;
        const lon = coords.longitude;

        try {
          const res = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}`);
          const data = await res.json();
          const address = data.display_name || `${lat}, ${lon}`;

          // Save for all pages
          localStorage.setItem("user_location", address);

          // Autofill if field exists
          if (locationInput) locationInput.value = address;
        } catch {
          localStorage.setItem("user_location", `${lat}, ${lon}`);
          if (locationInput) locationInput.value = `${lat}, ${lon}`;
        }
      },
      (err) => {
        console.warn("Geolocation error:", err);
        if (locationInput) locationInput.value = "Unable to fetch location";
      }
    );
  }

  // Attach to all arrow buttons
  detectButtons.forEach(btn => btn.addEventListener("click", detectLocation));

  // Auto-fill from storage if available
  if (locationInput && localStorage.getItem("user_location")) {
    locationInput.value = localStorage.getItem("user_location");
  }
});
