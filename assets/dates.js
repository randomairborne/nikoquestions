document.querySelectorAll("[data-timestamp]").forEach((elm) => {
    console.log(elm)
  elm.innerText = new Date(
    parseInt(elm.dataset.timestamp) * 1000,
  ).toLocaleString();
});
