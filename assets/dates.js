document.querySelectorAll("[data-timestamp]").forEach((elm) => {
  elm.innerText = new Date(
    parseInt(elm.dataset.timestamp) * 1000,
  ).toLocaleString();
});
