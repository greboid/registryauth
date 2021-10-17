document.addEventListener("click", (event) => {
    if (event.target.classList.contains("tagList")) {
        event.target.closest("td").classList.toggle("showinfo")
    }
});