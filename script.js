

(function () {
  "use strict";

  const prefersReducedMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)"
  ).matches;

  /* 1. HELPERS --------------------------------------------- */
  const $ = (sel, ctx = document) => ctx.querySelector(sel);
  const $$ = (sel, ctx = document) => Array.from(ctx.querySelectorAll(sel));
  const on = (el, evt, cb, opts) => el && el.addEventListener(evt, cb, opts);

  /* 2. NAVBAR ---------------------------------------------- */
  const nav = $("#nav");
  const navToggle = $("#navToggle");
  const navMobile = $("#navMobile");
  const scrollProgress = $("#scrollProgress");

  function setNavState() {
    const y = window.scrollY;
    if (nav) {
      nav.setAttribute("data-state", y > 40 ? "scrolled" : "top");
    }
    if (scrollProgress) {
      const h =
        document.documentElement.scrollHeight - window.innerHeight;
      const pct = h > 0 ? (y / h) * 100 : 0;
      scrollProgress.style.width = pct + "%";
    }
  }
  setNavState();
  on(window, "scroll", setNavState, { passive: true });

  function closeMobileMenu() {
    if (!navMobile || !navToggle) return;
    navMobile.classList.remove("is-open");
    navMobile.setAttribute("aria-hidden", "true");
    navToggle.setAttribute("aria-expanded", "false");
    navToggle.setAttribute("aria-label", "Open menu");
  }
  function openMobileMenu() {
    if (!navMobile || !navToggle) return;
    navMobile.classList.add("is-open");
    navMobile.setAttribute("aria-hidden", "false");
    navToggle.setAttribute("aria-expanded", "true");
    navToggle.setAttribute("aria-label", "Close menu");
  }
  on(navToggle, "click", () => {
    const open = navMobile.classList.contains("is-open");
    open ? closeMobileMenu() : openMobileMenu();
  });
  $$("[data-close]").forEach((el) =>
    on(el, "click", closeMobileMenu)
  );

  /* 3. SMOOTH SCROLL + ACTIVE LINK ------------------------- */
  const navLinks = $$("[data-nav]");
  const sectionsForActive = $$("main section[id], main #home");

  navLinks.forEach((link) => {
    on(link, "click", (e) => {
      const href = link.getAttribute("href") || "";
      if (href.startsWith("#") && href.length > 1) {
        const target = $(href);
        if (target) {
          e.preventDefault();
          const top =
            target.getBoundingClientRect().top + window.scrollY - 70;
          window.scrollTo({ top, behavior: "smooth" });
        }
      }
    });
  });

  /* Active section indicator */
  if (sectionsForActive.length && "IntersectionObserver" in window) {
    const linkById = {};
    navLinks.forEach((l) => {
      const h = l.getAttribute("href");
      if (h && h.startsWith("#")) linkById[h.slice(1)] = l;
    });
    const activeObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const id = entry.target.id;
            navLinks.forEach((l) => l.classList.remove("is-active"));
            const match = linkById[id];
            if (match) match.classList.add("is-active");
          }
        });
      },
      { rootMargin: "-45% 0px -50% 0px", threshold: 0 }
    );
    sectionsForActive.forEach((s) => activeObserver.observe(s));
  }

  /* 4. REVEAL ON SCROLL ------------------------------------ */
  const revealEls = $$("[data-reveal]");
  if (prefersReducedMotion) {
    revealEls.forEach((el) => el.classList.add("is-visible"));
  } else if ("IntersectionObserver" in window) {
    const revealObserver = new IntersectionObserver(
      (entries, obs) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const delay = entry.target.getAttribute("data-reveal-delay");
            if (delay)
              entry.target.style.setProperty("--reveal-delay", delay);
            entry.target.classList.add("is-visible");
            obs.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -8% 0px" }
    );
    revealEls.forEach((el) => revealObserver.observe(el));
  } else {
    revealEls.forEach((el) => el.classList.add("is-visible"));
  }

  /* Vertical timeline items: also toggle is-visible for dot glow */
  const vtimelineItems = $$(".vtimeline__item");
  if ("IntersectionObserver" in window) {
    const vtObserver = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) e.target.classList.add("is-visible");
        });
      },
      { threshold: 0.5 }
    );
    vtimelineItems.forEach((i) => vtObserver.observe(i));
  }

  /* 5. HERO PHOTO INTRO ------------------------------------ */
  // Hero image loads eagerly; subtle intro handled by reveal animation.

  /* 6. HERO PHOTO SUBTLE PARALLAX -------------------------- */
  const heroPhoto = $(".hero__photo img");
  if (heroPhoto && !prefersReducedMotion && window.innerWidth > 768) {
    let pendingRaf = false;
    let mx = 0,
      my = 0;
    const update = () => {
      pendingRaf = false;
      const cx = window.innerWidth / 2;
      const cy = window.innerHeight / 2;
      const rx = (my - cy) / cy;
      const ry = (mx - cx) / cx;
      heroPhoto.style.transform = `scale(1.04) translate(${ry * 8}px, ${rx * 8}px)`;
    };
    on(window, "mousemove", (e) => {
      mx = e.clientX;
      my = e.clientY;
      if (!pendingRaf) {
        pendingRaf = true;
        requestAnimationFrame(update);
      }
    });
  }

  /* 7. HERO LENS SEARCH DEMO ------------------------------- */
  const lensSearchInput = $("#lensSearchInput");
  const lensSearchSuggestions = $("#lensSearchSuggestions");
  const lensSearchResult = $("#lensSearchResult");
  const lensSearchLoading = $("#lensSearchLoading");
  const lensSearchOutput = $("#lensSearchOutput");
  const lensSearchBtn = $("#lensSearchBtn");
  const lensSearchBar = $("#lensSearchBar");

  const lensMemoryResults = {
    childhood: {
      title: "CHILDHOOD MEMORIES",
      items: [
        ["24", "Photos"],
        ["8", "Videos"],
        ["3", "Stories"],
        ["2", "Voice Memories"],
      ],
    },
    family: {
      title: "FAMILY MEMORIES",
      items: [
        ["42", "Photos"],
        ["11", "Videos"],
        ["6", "Stories"],
        ["4", "Voice Memories"],
      ],
    },
    "2018": {
      title: "MEMORIES FROM 2018",
      items: [
        ["18", "Photos"],
        ["5", "Videos"],
        ["2", "Stories"],
        ["1", "Voice Memory"],
      ],
    },
    milestones: {
      title: "YOUR BIGGEST MILESTONES",
      items: [
        ["31", "Photos"],
        ["9", "Videos"],
        ["7", "Stories"],
        ["3", "Voice Memories"],
      ],
    },
  };

  function runLensSearch(key) {
    if (!lensSearchResult) return;
    const result = lensMemoryResults[key];
    if (!result) return;
    if (lensSearchSuggestions) lensSearchSuggestions.hidden = true;
    lensSearchResult.hidden = false;
    lensSearchOutput.hidden = true;
    lensSearchLoading.hidden = false;
    setTimeout(() => {
      lensSearchLoading.hidden = true;
      lensSearchOutput.hidden = false;
      lensSearchOutput.innerHTML =
        `<h4>${result.title}</h4><ul>` +
        result.items
          .map(([n, label]) => `<li><b>${n}</b> ${label}</li>`)
          .join("") +
        `</ul>`;
    }, 1500);
  }

  if (lensSearchBar) {
    on(lensSearchInput, "focus", () => {
      if (lensSearchSuggestions) lensSearchSuggestions.hidden = false;
    });
    on(lensSearchInput, "blur", () => {
      setTimeout(() => {
        if (lensSearchSuggestions) lensSearchSuggestions.hidden = true;
      }, 180);
    });
    on(lensSearchInput, "keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        const v = lensSearchInput.value.trim().toLowerCase();
        const matchKey = Object.keys(lensMemoryResults).find((k) =>
          v.includes(k)
        );
        if (matchKey) runLensSearch(matchKey);
        else if (v) {
          lensSearchResult.hidden = false;
          lensSearchLoading.hidden = true;
          lensSearchOutput.hidden = false;
          lensSearchOutput.innerHTML =
            '<p class="ask__fallback">This is a demo of the Legacy Lens experience. Your real memories will become searchable once your account and archive are connected.</p>';
        }
      }
    });
    on(lensSearchBtn, "click", () => {
      const v = (lensSearchInput.value || "").trim().toLowerCase();
      const matchKey = Object.keys(lensMemoryResults).find((k) =>
        v.includes(k)
      );
      if (matchKey) runLensSearch(matchKey);
    });
    $$("#lensSearchSuggestions [data-suggestion]").forEach((btn) => {
      on(btn, "click", () => {
        const key = btn.getAttribute("data-suggestion");
        if (lensSearchInput) lensSearchInput.value = btn.textContent;
        runLensSearch(key);
      });
    });
  }

  /* 8. SCATTER → GATHER ------------------------------------ */
  const scatter = $("#scatter");
  if (scatter && "IntersectionObserver" in window) {
    const sObs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            setTimeout(() => scatter.classList.add("is-gathered"), 900);
            sObs.unobserve(e.target);
          }
        });
      },
      { threshold: 0.5 }
    );
    sObs.observe(scatter);
  }

  /* 9. MEMORY LENS HORIZONTAL TIMELINE --------------------- */
  const ttTrack = $("#ttTrack");
  const ttHandles = $("#ttHandles");
  const ttProgress = $("#ttProgress");
  const ttYear = $("#ttYear");
  const ttTitle = $("#ttTitle");
  const ttMeta = $("#ttMeta");

  const ttData = [
    {
      year: "2008",
      title: "The First Photo",
      img: "https://images.pexels.com/photos/7665662/pexels-photo-7665662.jpeg?auto=compress&cs=tinysrgb&h=600&w=900",
      meta: [
        ["1", "Photo"],
        ["1", "Story"],
      ],
    },
    {
      year: "2012",
      title: "Childhood Adventures",
      img: "https://images.pexels.com/photos/5274654/pexels-photo-5274654.jpeg?auto=compress&cs=tinysrgb&h=600&w=900",
      meta: [
        ["8", "Photos"],
        ["2", "Videos"],
        ["1", "Story"],
      ],
    },
    {
      year: "2016",
      title: "First Day of University",
      img: "https://images.pexels.com/photos/4709903/pexels-photo-4709903.jpeg?auto=compress&cs=tinysrgb&h=600&w=900",
      meta: [
        ["3", "Photos"],
        ["1", "Video"],
        ["2", "Stories"],
      ],
    },
    {
      year: "2020",
      title: "First Professional Project",
      img: "https://images.pexels.com/photos/7845094/pexels-photo-7845094.jpeg?auto=compress&cs=tinysrgb&h=600&w=900",
      meta: [
        ["12", "Photos"],
        ["4", "Videos"],
        ["3", "Notes"],
      ],
    },
    {
      year: "2024",
      title: "A Milestone Year",
      img: "https://images.pexels.com/photos/35487003/pexels-photo-35487003.jpeg?auto=compress&cs=tinysrgb&h=600&w=900",
      meta: [
        ["22", "Photos"],
        ["6", "Videos"],
        ["4", "Stories"],
      ],
    },
    {
      year: "2026",
      title: "Today",
      img: "https://images.pexels.com/photos/6667305/pexels-photo-6667305.jpeg?auto=compress&cs=tinysrgb&h=600&w=900",
      meta: [
        ["5", "Photos"],
        ["1", "Video"],
        ["1", "Note"],
      ],
    },
  ];

  let ttActive = 2;

  function renderTimelineHandles() {
    if (!ttHandles) return;
    ttHandles.innerHTML = "";
    ttData.forEach((_, i) => {
      const h = document.createElement("span");
      h.className = "tt-handle" + (i === ttActive ? " is-active" : "");
      h.setAttribute("role", "button");
      h.setAttribute("tabindex", "0");
      h.setAttribute("aria-label", `Year ${ttData[i].year}`);
      on(h, "click", () => setActiveTimeline(i));
      on(h, "keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          setActiveTimeline(i);
        }
      });
      ttHandles.appendChild(h);
    });
  }

  function setActiveTimeline(i) {
    ttActive = Math.max(0, Math.min(ttData.length - 1, i));
    const d = ttData[ttActive];
    const ttImg = $("#ttImg");
    if (ttImg) {
      ttImg.style.opacity = "0";
      setTimeout(() => {
        ttImg.src = d.img;
        ttImg.alt = d.title + " — " + d.year;
        ttImg.style.opacity = "1";
      }, 200);
    }
    if (ttYear) {
      ttYear.style.opacity = "0";
      setTimeout(() => {
        ttYear.textContent = d.year;
        ttYear.style.opacity = "1";
      }, 160);
    }
    if (ttTitle) ttTitle.textContent = d.title;
    if (ttMeta)
      ttMeta.innerHTML = d.meta
        .map(([n, l]) => `<li><b>${n}</b> ${l}</li>`)
        .join("");
    if (ttProgress)
      ttProgress.style.width =
        (ttActive / (ttData.length - 1)) * 100 + "%";
    if (ttTrack)
      ttTrack.setAttribute("aria-valuenow", String(ttActive));
    $$(".tt-handle", ttHandles).forEach((h, idx) =>
      h.classList.toggle("is-active", idx === ttActive)
    );
  }

  if (ttTrack) {
    renderTimelineHandles();
    setActiveTimeline(2);

    let dragging = false;
    const moveFromX = (clientX) => {
      const rect = ttTrack.getBoundingClientRect();
      const ratio = (clientX - rect.left) / rect.width;
      const idx = Math.round(ratio * (ttData.length - 1));
      if (idx !== ttActive) setActiveTimeline(idx);
    };
    on(ttTrack, "mousedown", (e) => {
      dragging = true;
      moveFromX(e.clientX);
    });
    on(window, "mousemove", (e) => {
      if (dragging) moveFromX(e.clientX);
    });
    on(window, "mouseup", () => (dragging = false));
    on(ttTrack, "touchstart", (e) => {
      dragging = true;
      if (e.touches[0]) moveFromX(e.touches[0].clientX);
    }, { passive: true });
    on(ttTrack, "touchmove", (e) => {
      if (dragging && e.touches[0]) moveFromX(e.touches[0].clientX);
    }, { passive: true });
    on(ttTrack, "touchend", () => (dragging = false));
    on(ttTrack, "keydown", (e) => {
      if (e.key === "ArrowRight") setActiveTimeline(ttActive + 1);
      if (e.key === "ArrowLeft") setActiveTimeline(ttActive - 1);
    });
  }

  /* 10. ASK YOUR MEMORIES DEMO ----------------------------- */
  const askInput = $("#askInput");
  const askBtn = $("#askBtn");
  const askResponse = $("#askResponse");
  const askLoading = $("#askLoading");
  const askOutput = $("#askOutput");

  const askData = {
    childhood: {
      head: "I FOUND IT.",
      date: "2006 – 2012",
      event: "Your Childhood Memories",
      stats: [
        ["24", "Photos"],
        ["8", "Videos"],
        ["3", "Voice Memories"],
        ["5", "Stories"],
      ],
      cards: ["📷", "🎥", "🎙", "📝"],
    },
    family: {
      head: "I FOUND IT.",
      date: "Across many years",
      event: "Memories With Your Family",
      stats: [
        ["42", "Photos"],
        ["11", "Videos"],
        ["6", "Voice Memories"],
        ["8", "Stories"],
      ],
      cards: ["📷", "🎥", "🎙", "📝"],
    },
    graduation: {
      head: "I FOUND IT.",
      date: "June 18, 2021",
      event: "Graduation Day",
      stats: [
        ["12", "Photos"],
        ["2", "Videos"],
        ["1", "Voice Memory"],
        ["1", "Story"],
      ],
      cards: ["🎓", "📷", "🎥", "🎙"],
    },
    travel: {
      head: "I FOUND IT.",
      date: "Summers 2017 – 2019",
      event: "Your Travel Memories",
      stats: [
        ["58", "Photos"],
        ["14", "Videos"],
        ["3", "Voice Notes"],
        ["2", "Stories"],
      ],
      cards: ["✈️", "📷", "🎥", "📍"],
    },
    school: {
      head: "I FOUND IT.",
      date: "2010 – 2018",
      event: "School Days",
      stats: [
        ["19", "Photos"],
        ["3", "Videos"],
        ["2", "Stories"],
      ],
      cards: ["🏫", "📷", "📝", "🎥"],
    },
    2020: {
      head: "I FOUND IT.",
      date: "2020",
      event: "A Year That Changed Everything",
      stats: [
        ["33", "Photos"],
        ["7", "Videos"],
        ["4", "Notes"],
        ["2", "Voice Memories"],
      ],
      cards: ["📷", "🎥", "🎙", "📝"],
    },
  };

  function runAsk(query) {
    if (!askResponse) return;
    const q = query.trim().toLowerCase();
    if (!q) return;
    const key = Object.keys(askData).find((k) => q.includes(k));
    askResponse.hidden = false;
    askLoading.hidden = false;
    askOutput.hidden = true;
    if (askInput) askInput.value = query;
    setTimeout(() => {
      askLoading.hidden = true;
      askOutput.hidden = false;
      if (!key) {
        askOutput.innerHTML =
          '<p class="ask__fallback">This is a demo of the Legacy Lens experience. Your real memories will become searchable once your account and archive are connected.</p>';
        return;
      }
      const d = askData[key];
      askOutput.innerHTML =
        `<h3>${d.head}</h3>` +
        `<p class="ask__date">${d.date}</p>` +
        `<p class="ask__event">${d.event}</p>` +
        `<ul>${d.stats
          .map(([n, l]) => `<li><b>${n}</b> ${l}</li>`)
          .join("")}</ul>` +
        `<div class="ask__cards">${d.cards
          .map((c) => `<div class="ask__mini-card">${c}</div>`)
          .join("")}</div>`;
    }, 1300);
  }

  if (askBtn && askInput) {
    on(askBtn, "click", () => runAsk(askInput.value));
    on(askInput, "keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        runAsk(askInput.value);
      }
    });
    $$("[data-ask]").forEach((btn) => {
      on(btn, "click", () => {
        const q = btn.getAttribute("data-ask");
        runAsk(q);
        askResponse.scrollIntoView({ behavior: "smooth", block: "center" });
      });
    });
  }

  /* 11. FILES → STORIES TRANSFORM -------------------------- */
  const transform = $("#transform");
  if (transform && "IntersectionObserver" in window) {
    const tObs = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            transform.classList.add("is-active");
            tObs.unobserve(e.target);
          }
        });
      },
      { threshold: 0.4 }
    );
    tObs.observe(transform);
  }

  /* 12. TIME CAPSULE MODAL --------------------------------- */
  const modal = $("#modal");
  const capsuleBtn = $("#capsuleBtn");

  function openModal() {
    if (!modal) return;
    modal.hidden = false;
    document.body.style.overflow = "hidden";
    const focusable = modal.querySelector("button, [tabindex]");
    if (focusable) focusable.focus();
  }
  function closeModal() {
    if (!modal) return;
    modal.hidden = true;
    document.body.style.overflow = "";
  }
  if (capsuleBtn) on(capsuleBtn, "click", openModal);
  $$("[data-modal-close]").forEach((el) => on(el, "click", closeModal));

  /* 13. AI MEMORY STORY PLAY ------------------------------- */
  const memoPlay = $("#memoPlay");
  const waveform = $("#waveform");
  let waveTimer = null;
  if (memoPlay && waveform) {
    on(memoPlay, "click", () => {
      const playing = memoPlay.classList.toggle("is-playing");
      waveform.classList.toggle("is-playing", playing);
      memoPlay.querySelector(".memo-story__play-text").textContent = playing
        ? "Pause"
        : "Play";
      if (playing) {
        waveTimer = setTimeout(() => {
          memoPlay.classList.remove("is-playing");
          waveform.classList.remove("is-playing");
          memoPlay.querySelector(".memo-story__play-text").textContent = "Play";
        }, 8000);
      } else if (waveTimer) {
        clearTimeout(waveTimer);
      }
    });
  }

  /* 14. SIGN UP / SIGN IN PLACEHOLDER ---------------------- */
  const toast = $("#toast");
  const toastTitle = $("#toastTitle");
  const toastBody = $("#toastBody");
  let toastTimer = null;

  function showToast(title, body) {
    if (!toast || !toastTitle || !toastBody) return;
    toastTitle.textContent = title;
    toastBody.textContent = body;
    toast.hidden = false;
    requestAnimationFrame(() => toast.classList.add("is-visible"));
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast.classList.remove("is-visible");
      setTimeout(() => (toast.hidden = true), 400);
    }, 3600);
  }

  const authMessages = {
    signup: {
      title: "Your Legacy begins here.",
      body: "Authentication will be connected soon.",
    },
    signin: {
      title: "Welcome back.",
      body: "Secure authentication will be connected soon.",
    },
  };

  function handleAuth(action) {
    const msg = authMessages[action];
    if (msg) showToast(msg.title, msg.body);
  }

  // Centralized handler for any element with data-action="signup|signin"
  document.addEventListener("click", (e) => {
    const target = e.target.closest("[data-action]");
    if (!target) return;
    const action = target.getAttribute("data-action");
    if (action === "signup" || action === "signin") {
      e.preventDefault();
      handleAuth(action);
      // If inside modal, also close it
      if (modal && !modal.hidden) closeModal();
    }
  });

  /* 15. FOOTER PLACEHOLDER LINKS --------------------------- */
  $$("[data-placeholder]").forEach((el) => {
    on(el, "click", (e) => {
      e.preventDefault();
      showToast("Coming soon.", "This page will be available in a future update.");
    });
  });

  /* 16. ESCAPE & GLOBAL A11Y ------------------------------- */
  on(document, "keydown", (e) => {
    if (e.key === "Escape") {
      closeMobileMenu();
      if (modal && !modal.hidden) closeModal();
    }
  });

  // Click outside mobile menu closes it
  on(document, "click", (e) => {
    if (
      navMobile &&
      navMobile.classList.contains("is-open") &&
      !navMobile.contains(e.target) &&
      !navToggle.contains(e.target)
    ) {
      closeMobileMenu();
    }
  });
})();
