document.addEventListener("click", (event) => {
    if (event.target.classList.contains("copy")) {
        if (!navigator.clipboard) {
            console.log("Unable to copy")
        }
        let sha = event.target.previousElementSibling.textContent.trim()
        let image = event.target.closest('tr').children[0].textContent.trim()
        let registry = document.title.trim()
        navigator.clipboard.writeText(`${registry}/${image}@${sha}`)
            .catch(e => console.log(`Error copying ${e}`))
    } else if (event.target.closest("td") != null && event.target.closest("td").classList.contains("tags")) {
        event.target.closest("td").classList.toggle("showinfo")
    }
});
