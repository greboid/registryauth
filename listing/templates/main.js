document.addEventListener("click", (event) => {
    if (event.target.classList.contains("copy")) {
        if (!navigator.clipboard) {
            console.log("Unable to copy")
        }
        let sha = event.target.previousElementSibling.textContent
        let tag = event.target.previousElementSibling.previousElementSibling.textContent
        let registry = document.title
        navigator.clipboard.writeText(`${registry}/${tag}:${sha}`)
            .catch(e => console.log(`Error copying ${e}`))
    } else if (event.target.closest("td").classList.contains("tags")) {
        event.target.closest("td").classList.toggle("showinfo")
    }
});
