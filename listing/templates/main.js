document.addEventListener("click", (event) => {
    if (event.target.classList.contains("copy")) {
        if (!navigator.clipboard) {
            console.log("Unable to copy")
            return
        }
        navigator.clipboard.writeText(event.target.dataset.ref)
            .catch(e => console.log(`Error copying ${e}`))
    } else if (event.target.closest("td") != null && event.target.closest("td").classList.contains("tags")) {
        event.target.closest("td").classList.toggle("showinfo")
    }
});
