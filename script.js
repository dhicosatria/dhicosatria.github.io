const shareButton = document.querySelector(".share-button");
const toast = document.querySelector(".toast");
const year = document.querySelector("#year");

year.textContent = new Date().getFullYear();

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 2200);
}

shareButton.addEventListener("click", async () => {
  const shareData = {
    title: document.title,
    text: "Lihat Bio Link saya di sini.",
    url: window.location.href,
  };

  try {
    if (navigator.share) {
      await navigator.share(shareData);
      return;
    }

    await navigator.clipboard.writeText(window.location.href);
    showToast("Tautan disalin");
  } catch (error) {
    if (error.name !== "AbortError") {
      showToast("Tidak dapat membagikan tautan");
    }
  }
});
