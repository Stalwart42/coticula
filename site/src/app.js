document.querySelectorAll("button.copy").forEach(function (b) {
  b.addEventListener("click", function () {
    var t = document.getElementById(b.getAttribute("data-target"));
    if (!t || !navigator.clipboard) return;
    navigator.clipboard.writeText(t.textContent.trim()).then(function () {
      var o = b.textContent; b.textContent = "Copied"; setTimeout(function () { b.textContent = o; }, 1400);
    });
  });
});

var form = document.getElementById("wait");
if (form) {
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var msg = document.getElementById("wait-msg");
    var btn = form.querySelector("button");
    var data = {
      email: form.email.value.trim(),
      role: form.role.value,
      website: form.website.value
    };
    btn.disabled = true; msg.className = ""; msg.textContent = "Adding you…";
    fetch("/api/waitlist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (res) {
        msg.className = res.ok ? "ok" : "err";
        msg.textContent = res.j.message || (res.ok ? "You're on the list." : "Something went wrong.");
        if (res.ok) form.reset();
      })
      .catch(function () { msg.className = "err"; msg.textContent = "Network error — please try again."; })
      .finally(function () { btn.disabled = false; });
  });
}
