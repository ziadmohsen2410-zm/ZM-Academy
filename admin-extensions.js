"use strict";
(() => {
  const typeNames = { heading: "عنوان", text: "نص", button: "زر", card: "بطاقة", image: "صورة", alert: "تنبيه", section: "قسم", spacer: "مسافة", video: "رابط فيديو" };
  let builderDoc = { version: 1, blocks: [] };
  let aiBuilderSuggestion = null;
  let loadedBuilderSlug = "";
  let quizQuestionDrafts = [];

  const node = (tag, attrs = {}, content = "") => {
    const n = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "class") n.className = value;
      else if (key === "text") n.textContent = value;
      else if (key === "style" && value && typeof value === "object") Object.assign(n.style, value);
      else if (key.startsWith("on") && typeof value === "function") n.addEventListener(key.slice(2).toLowerCase(), value);
      else if (value !== undefined && value !== null) n.setAttribute(key, String(value));
    }
    if (content !== "") n.textContent = content;
    return n;
  };
  const safeText = (value, max = 3000) => String(value ?? "").slice(0, max);
  const slugValue = () => {
    const slug = safeText(el("builderSlug")?.value, 60).trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{1,59}$/.test(slug)) throw new Error("معرّف الصفحة يجب أن يتكون من 2 إلى 60 حرفًا إنجليزيًا صغيرًا أو رقمًا أو شرطة.");
    return slug;
  };
  const idValue = () => (crypto.randomUUID ? crypto.randomUUID().replace(/-/g, "").slice(0, 16) : `b${Date.now()}${Math.random().toString(36).slice(2, 8)}`);
  const setStatus = (text) => { if (el("builderStatus")) el("builderStatus").textContent = text; };

  function newBlock(type) {
    const defaults = {
      heading: { title: "عنوان جديد", text: "" }, text: { title: "", text: "اكتب النص هنا" },
      button: { title: "", text: "", buttonText: "ابدأ الآن", href: "#" },
      card: { title: "عنوان البطاقة", text: "وصف البطاقة" }, image: { title: "", text: "", src: "", alt: "وصف الصورة" },
      alert: { title: "تنبيه", text: "نص التنبيه" }, section: { title: "قسم جديد", text: "وصف القسم" },
      spacer: { title: "", text: "" }, video: { title: "شاهد الفيديو", text: "", href: "https://example.com" }
    };
    return { id: idValue(), type, visible: true, content: defaults[type] || { title: "", text: "" }, style: { padding: type === "spacer" ? 20 : 14, radius: 14, align: "right" }, responsive: {} };
  }

  function blockField(block, key, label, multiline = false, placeholder = "") {
    const wrap = node("div");
    const lab = node("label", { text: label });
    const input = node(multiline ? "textarea" : "input", { maxlength: key === "text" ? 3000 : 1000, placeholder, rows: multiline ? 3 : undefined });
    input.value = safeText(block.content?.[key]);
    input.addEventListener("input", () => { block.content[key] = input.value; renderBuilderPreview(); });
    wrap.append(lab, input);
    return wrap;
  }

  function renderBuilderBlocks() {
    const host = el("builderBlocks");
    if (!host) return;
    host.replaceChildren();
    if (!builderDoc.blocks.length) {
      host.append(node("p", { class: "hint", text: "لا توجد عناصر بعد. استخدم أزرار الإضافة بالأعلى." }));
      renderBuilderPreview();
      return;
    }
    builderDoc.blocks.forEach((block, index) => {
      const card = node("article", { class: "zmz-block" });
      card.draggable = true;
      card.dataset.blockIndex = String(index);
      card.setAttribute("aria-label", `عنصر ${index + 1}؛ اسحب لتغيير الترتيب`);
      card.addEventListener("dragstart", (event) => {
        event.dataTransfer.effectAllowed = "move";
        event.dataTransfer.setData("text/plain", String(index));
        card.classList.add("is-dragging");
      });
      card.addEventListener("dragend", () => card.classList.remove("is-dragging"));
      card.addEventListener("dragover", (event) => { event.preventDefault(); event.dataTransfer.dropEffect = "move"; });
      card.addEventListener("drop", (event) => {
        event.preventDefault();
        const source = Number(event.dataTransfer.getData("text/plain"));
        if (!Number.isInteger(source) || source < 0 || source >= builderDoc.blocks.length || source === index) return;
        const [moved] = builderDoc.blocks.splice(source, 1);
        builderDoc.blocks.splice(index, 0, moved);
        renderBuilderBlocks();
      });
      const head = node("div", { class: "zmz-block-head" });
      head.append(node("strong", { text: `${index + 1}. ${typeNames[block.type] || block.type}` }));
      const tools = node("div", { class: "zmz-block-tools" });
      const moveUp = node("button", { type: "button", text: "↑", title: "تحريك لأعلى" });
      const moveDown = node("button", { type: "button", text: "↓", title: "تحريك لأسفل" });
      const toggle = node("button", { type: "button", text: block.visible === false ? "إظهار" : "إخفاء" });
      const remove = node("button", { type: "button", text: "حذف" });
      moveUp.disabled = index === 0; moveDown.disabled = index === builderDoc.blocks.length - 1;
      moveUp.addEventListener("click", () => reorderBlock(index, -1));
      moveDown.addEventListener("click", () => reorderBlock(index, 1));
      toggle.addEventListener("click", () => { block.visible = block.visible === false; renderBuilderBlocks(); });
      remove.addEventListener("click", () => { builderDoc.blocks.splice(index, 1); renderBuilderBlocks(); });
      tools.append(moveUp, moveDown, toggle, remove); head.append(tools); card.append(head);

      if (["heading", "card", "alert", "section", "button", "video"].includes(block.type)) card.append(blockField(block, "title", "العنوان"));
      if (block.type !== "spacer" && block.type !== "image") card.append(blockField(block, "text", "النص", true));
      if (block.type === "button" || block.type === "video") {
        card.append(blockField(block, "buttonText", "نص الرابط"), blockField(block, "href", "الرابط (HTTPS أو رابط داخلي)"));
      }
      if (block.type === "image") card.append(blockField(block, "src", "رابط الصورة HTTPS أو /assets/... أو /api/media/ID"), blockField(block, "alt", "الوصف البديل"));

      const styleGrid = node("div", { class: "zmz-grid" });
      const colorWrap = node("div"); colorWrap.append(node("label", { text: "لون النص" }));
      const color = node("input", { type: "color" }); color.value = /^#[0-9a-f]{6}$/i.test(block.style?.color || "") ? block.style.color : "#eaf3ff";
      color.addEventListener("input", () => { block.style.color = color.value; renderBuilderPreview(); }); colorWrap.append(color);
      const bgWrap = node("div"); bgWrap.append(node("label", { text: "لون الخلفية" }));
      const bg = node("input", { type: "color" }); bg.value = /^#[0-9a-f]{6}$/i.test(block.style?.background || "") ? block.style.background : "#172744";
      bg.addEventListener("input", () => { block.style.background = bg.value; renderBuilderPreview(); }); bgWrap.append(bg);
      const alignWrap = node("div"); alignWrap.append(node("label", { text: "المحاذاة" }));
      const align = node("select"); [["right", "يمين"], ["center", "وسط"], ["left", "يسار"]].forEach(([v, t]) => align.append(node("option", { value: v, text: t }))); align.value = block.style?.align || "right";
      align.addEventListener("change", () => { block.style.align = align.value; renderBuilderPreview(); }); alignWrap.append(align);
      styleGrid.append(colorWrap, bgWrap, alignWrap); card.append(styleGrid);

      const device = el("builderDevice")?.value || "desktop";
      block.responsive ||= {}; block.responsive[device] ||= {};
      const deviceWrap = node("div", { class: "zmz-grid" });
      const hideLabel = node("label", { class: "check" });
      const hide = node("input", { type: "checkbox" }); hide.checked = block.responsive[device].hidden === true;
      hide.addEventListener("change", () => { block.responsive[device].hidden = hide.checked; renderBuilderPreview(); });
      hideLabel.append(hide, document.createTextNode(` إخفاء على ${device === "mobile" ? "الهاتف" : device === "tablet" ? "التابلت" : "الكمبيوتر"}`));
      const widthWrap = node("div"); widthWrap.append(node("label", { text: "عرض العنصر (%)" }));
      const width = node("input", { type: "number", min: "20", max: "100", placeholder: "100" }); width.value = block.responsive[device].width ?? "";
      width.addEventListener("input", () => { const v = Number(width.value); if (!width.value) delete block.responsive[device].width; else if (v >= 20 && v <= 100) block.responsive[device].width = v; renderBuilderPreview(); });
      widthWrap.append(width); deviceWrap.append(hideLabel, widthWrap); card.append(deviceWrap);
      host.append(card);
    });
    renderBuilderPreview();
  }

  function reorderBlock(index, delta) {
    const next = index + delta;
    if (next < 0 || next >= builderDoc.blocks.length) return;
    [builderDoc.blocks[index], builderDoc.blocks[next]] = [builderDoc.blocks[next], builderDoc.blocks[index]];
    renderBuilderBlocks();
  }

  function renderBuilderPreview() {
    const host = el("builderPreview");
    if (!host) return;
    host.replaceChildren();
    const device = el("builderDevice")?.value || "desktop";
    const width = device === "mobile" ? "375px" : device === "tablet" ? "768px" : "100%";
    const inner = node("div", { class: "zmz-preview-inner", style: { width: "100%", maxWidth: width } });
    const pageHeading = node("h3", { text: safeText(el("builderTitle")?.value || "معاينة الصفحة", 120) });
    inner.append(pageHeading);
    builderDoc.blocks.forEach((block) => {
      if (block.visible === false || block.responsive?.[device]?.hidden === true) return;
      const content = block.content || {}, style = block.style || {};
      const item = node("div", { class: `zmz-preview-item zmz-preview-${block.type}` });
      if (/^#[0-9a-f]{6}$/i.test(style.color || "")) item.style.color = style.color;
      if (/^#[0-9a-f]{6}$/i.test(style.background || "")) item.style.backgroundColor = style.background;
      item.style.textAlign = ["right", "center", "left"].includes(style.align) ? style.align : "right";
      if (Number.isFinite(Number(style.padding))) item.style.padding = `${Math.max(0, Math.min(64, Number(style.padding)))}px`;
      if (Number.isFinite(Number(style.radius))) item.style.borderRadius = `${Math.max(0, Math.min(48, Number(style.radius)))}px`;
      if (Number.isFinite(Number(style.fontSize))) item.style.fontSize = `${Math.max(12, Math.min(48, Number(style.fontSize)))}px`;
      const responsiveWidth = Number(block.responsive?.[device]?.width);
      if (responsiveWidth >= 20 && responsiveWidth <= 100) item.style.width = `${responsiveWidth}%`;
      if (block.type === "spacer") item.style.minHeight = `${Math.max(8, Math.min(120, Number(style.padding) || 20))}px`;
      else if (block.type === "image") {
        if (typeof content.src === "string" && (/^https:\/\//i.test(content.src) || /^\/assets\/[a-z0-9_./-]+$/i.test(content.src) || /^\/api\/media\/\d+$/.test(content.src))) {
          const imageSrc = content.src.startsWith("/api/media/") ? `${API}${content.src}` : content.src;
          const img = node("img", { src: imageSrc, alt: safeText(content.alt, 180), loading: "lazy" }); item.append(img);
        } else item.append(node("span", { text: "أضف رابط صورة HTTPS صالحًا" }));
      } else if (block.type === "button" || block.type === "video") {
        if (content.title) item.append(node("strong", { text: safeText(content.title, 180) }));
        if (content.text) item.append(node("p", { text: safeText(content.text, 1000) }));
        const href = safeText(content.href, 1000);
        const label = safeText(content.buttonText || (block.type === "video" ? "فتح الفيديو" : "فتح الرابط"), 80);
        if (/^(https:\/\/|\/|#)/i.test(href)) item.append(node("a", { href, text: label, target: /^https:\/\//i.test(href) ? "_blank" : undefined, rel: "noopener noreferrer" }));
      } else {
        if (content.title) item.append(node(block.type === "heading" ? "h2" : "strong", { text: safeText(content.title, 180) }));
        if (content.text) item.append(node("p", { text: safeText(content.text, 3000) }));
      }
      inner.append(item);
    });
    host.append(inner);
  }

  window.builderAddBlock = (type) => {
    if (!typeNames[type]) return;
    builderDoc.blocks.push(newBlock(type));
    renderBuilderBlocks();
  };
  window.builderLoad = async () => {
    try {
      const slug = slugValue();
      const data = await request(`/api/admin/pages/${encodeURIComponent(slug)}`);
      el("builderTitle").value = data.page.title || "";
      builderDoc = data.page.draft && Array.isArray(data.page.draft.blocks) ? data.page.draft : { version: 1, blocks: [] };
      loadedBuilderSlug = slug;
      renderBuilderBlocks();
      await builderLoadVersions();
      setStatus(`حالة الصفحة: ${data.page.status} — آخر تحديث: ${data.page.updated_at || "لا يوجد"}`);
    } catch (error) { setStatus(error.message); }
  };
  window.builderSave = async () => {
    try {
      const slug = slugValue();
      const title = safeText(el("builderTitle").value, 120).trim();
      if (!title) throw new Error("اكتب عنوان الصفحة.");
      await request(`/api/admin/pages/${encodeURIComponent(slug)}`, "PUT", { title, document: builderDoc });
      loadedBuilderSlug = slug; setStatus("تم حفظ المسودة وإنشاء إصدار جديد."); await builderLoadVersions(); message("تم حفظ مسودة الصفحة.");
    } catch (error) { setStatus(error.message); message(error.message, "err"); }
  };
  window.builderPublish = async () => {
    try {
      const slug = slugValue();
      if (loadedBuilderSlug !== slug) throw new Error("حمّل الصفحة أو احفظها أولًا قبل النشر.");
      if (!confirm("سيتم نشر المسودة الحالية لتصبح متاحة عبر رابط الصفحة العامة. هل تريد المتابعة؟")) return;
      await request(`/api/admin/pages/${encodeURIComponent(slug)}/publish`, "POST", {});
      await builderLoad(); message("تم نشر الصفحة.");
    } catch (error) { message(error.message, "err"); }
  };
  window.builderLoadVersions = async () => {
    try {
      const slug = slugValue(); const data = await request(`/api/admin/pages/${encodeURIComponent(slug)}`);
      const select = el("builderRevision"); select.replaceChildren(node("option", { value: "", text: "اختر إصدارًا" }));
      (data.revisions || []).forEach((rev) => select.append(node("option", { value: rev.id, text: `#${rev.id} — ${rev.revision_type} — ${rev.created_at}` })));
    } catch (error) { setStatus(error.message); }
  };
  window.builderRestore = async () => {
    try {
      const slug = slugValue(); const revision = Number(el("builderRevision").value);
      if (!revision) throw new Error("اختر إصدارًا أولًا.");
      if (!confirm("سيتم وضع الإصدار المحدد كمسودة حالية دون نشره. هل تريد المتابعة؟")) return;
      await request(`/api/admin/pages/${encodeURIComponent(slug)}/restore/${revision}`, "POST", {});
      await builderLoad(); message("تمت استعادة الإصدار كمسودة.");
    } catch (error) { message(error.message, "err"); }
  };

  function renderQuizQuestionDrafts() {
    const host = el("quizQuestionDrafts"); if (!host) return;
    host.replaceChildren();
    if (!quizQuestionDrafts.length) { host.append(node("p", { class: "hint", text: "لم تتم إضافة أسئلة بعد." })); return; }
    quizQuestionDrafts.forEach((q, index) => {
      const row = node("div", { class: "zmz-row" });
      row.append(node("div", { class: "zmz-row-main" }));
      row.firstChild.append(node("strong", { text: `${index + 1}. ${q.prompt}` }), node("small", { text: `${q.type} · ${q.points} درجة` }));
      const remove = node("button", { type: "button", class: "secondary", text: "حذف" });
      remove.addEventListener("click", () => { quizQuestionDrafts.splice(index, 1); renderQuizQuestionDrafts(); });
      row.append(node("div", { class: "zmz-row-actions" })); row.lastChild.append(remove); host.append(row);
    });
  }
  window.addQuizQuestion = () => {
    const type = el("quizQuestionType").value, prompt = safeText(el("quizQuestionPrompt").value, 1200).trim(), points = Number(el("quizQuestionPoints").value);
    if (!prompt || !Number.isFinite(points) || points <= 0 || points > 100) return message("اكتب نص السؤال وحدد درجة صحيحة.", "err");
    const q = { type, prompt, points };
    if (type === "mcq") {
      q.options = el("quizOptions").value.split("\n").map((x) => x.trim()).filter(Boolean);
      q.correct_index = Number(el("quizCorrectIndex").value);
      if (q.options.length < 2 || q.options.length > 6 || !Number.isInteger(q.correct_index) || q.correct_index < 0 || q.correct_index >= q.options.length) return message("أدخل من اختيارين إلى ستة وحدد رقم الإجابة الصحيحة من صفر.", "err");
    }
    if (type === "true_false") q.correct_value = el("quizTrueFalse").value === "true";
    quizQuestionDrafts.push(q); el("quizQuestionPrompt").value = ""; renderQuizQuestionDrafts();
  };
  window.createQuiz = async () => {
    const payload = { title: el("quizTitle").value, grade: el("quizGrade").value, subject_id: el("quizSubject").value || null, duration_minutes: Number(el("quizDuration").value), max_attempts: Number(el("quizAttempts").value), questions: quizQuestionDrafts };
    try {
      if (!quizQuestionDrafts.length) throw new Error("أضف سؤالًا واحدًا على الأقل.");
      const result = await request("/api/admin/quizzes", "POST", payload);
      quizQuestionDrafts = []; renderQuizQuestionDrafts(); el("quizTitle").value = ""; el("quizQuestionPrompt").value = "";
      message(`تم إنشاء الاختبار رقم ${result.id} كمسودة.`); await loadQuizzes();
    } catch (error) { message(error.message, "err"); }
  };
  window.loadQuizzes = async () => {
    const host = el("quizzesList"); host.replaceChildren(node("p", { class: "hint", text: "جارٍ تحميل الاختبارات..." }));
    try {
      const data = await request("/api/admin/quizzes"); host.replaceChildren();
      if (!data.quizzes?.length) host.append(node("p", { class: "hint", text: "لا توجد اختبارات بعد." }));
      (data.quizzes || []).forEach((quiz) => {
        const row = node("div", { class: "zmz-row" }), main = node("div", { class: "zmz-row-main" });
        main.append(node("strong", { text: `${quiz.title} — ${quiz.grade}` }), node("small", { text: `#${quiz.id} · ${quiz.status} · ${quiz.question_count} سؤال · ${quiz.attempt_count} محاولة · ${quiz.duration_minutes} دقيقة` }));
        const actions = node("div", { class: "zmz-row-actions" });
        if (quiz.status === "draft") { const publish = node("button", { type: "button", text: "نشر" }); publish.addEventListener("click", async () => { if (!confirm("نشر الاختبار للطلاب المؤهلين؟")) return; try { await request(`/api/admin/quizzes/${quiz.id}/publish`, "POST", {}); await loadQuizzes(); message("تم نشر الاختبار."); } catch (e) { message(e.message, "err"); } }); actions.append(publish); }
        if (quiz.status !== "archived") { const archive = node("button", { type: "button", class: "secondary", text: "أرشفة" }); archive.addEventListener("click", async () => { if (!confirm("أرشفة الاختبار؟ ستظل المحاولات محفوظة.")) return; try { await request(`/api/admin/quizzes/${quiz.id}/archive`, "POST", {}); await loadQuizzes(); } catch (e) { message(e.message, "err"); } }); actions.append(archive); }
        row.append(main, actions); host.append(row);
      });
      await loadQuizAttempts();
    } catch (error) { host.replaceChildren(node("p", { class: "hint", text: error.message })); }
  };
  window.loadQuizAttempts = async () => {
    const host = el("quizAttemptsList"); host.replaceChildren(node("p", { class: "hint", text: "جارٍ تحميل المحاولات..." }));
    try {
      const data = await request("/api/admin/quiz-attempts?status=submitted"); host.replaceChildren();
      if (!data.attempts?.length) return host.append(node("p", { class: "hint", text: "لا توجد إجابات مقالية بانتظار المراجعة." }));
      data.attempts.forEach((attempt) => {
        const row = node("div", { class: "zmz-row" }), main = node("div", { class: "zmz-row-main" });
        main.append(node("strong", { text: `${attempt.student_name} — ${attempt.quiz_title}` }), node("small", { text: `محاولة #${attempt.id} · الدرجة الكلية ${attempt.max_score}` }));
        const grade = node("button", { type: "button", text: "مراجعة وتصحيح" });
        grade.addEventListener("click", async () => {
          try {
            const answerData = await request(`/api/admin/quiz-attempts/${attempt.id}/review`);
            const scoresText = prompt(`أدخل درجات الأسئلة المقالية بصيغة JSON.
الأسئلة: ${JSON.stringify(answerData.essays)}
مثال: {"12":5}`);
            if (scoresText === null) return;
            const essay_scores = JSON.parse(scoresText);
            const teacher_feedback = prompt("ملاحظات المدرس (اختياري):", "");
            await request(`/api/admin/quiz-attempts/${attempt.id}/grade`, "POST", { essay_scores, teacher_feedback: teacher_feedback || "" });
            await loadQuizAttempts(); message("تم حفظ التصحيح.");
          } catch (error) { message(error.message, "err"); }
        });
        row.append(main, node("div", { class: "zmz-row-actions" })); row.lastChild.append(grade); host.append(row);
      });
    } catch (error) { host.replaceChildren(node("p", { class: "hint", text: error.message })); }
  };

  window.loadParentRequests = async () => {
    const host = el("parentRequestsList"); host.replaceChildren(node("p", { class: "hint", text: "جارٍ تحميل الطلبات..." }));
    try {
      const data = await request("/api/admin/parent-link-requests"); host.replaceChildren();
      if (!data.requests?.length) return host.append(node("p", { class: "hint", text: "لا توجد طلبات ربط معلقة." }));
      data.requests.forEach((r) => {
        const row = node("div", { class: "zmz-row" }); const main = node("div", { class: "zmz-row-main" });
        main.append(node("strong", { text: `${r.parent_name} ↔ ${r.student_name}` }), node("small", { text: `ولي الأمر: ${r.parent_phone} — الطالب: ${r.student_phone} — ${r.grade}` }));
        const actions = node("div", { class: "zmz-row-actions" });
        const approve = node("button", { type: "button", text: "اعتماد" }); approve.addEventListener("click", () => reviewParentRequest(r.id, "approve"));
        const reject = node("button", { type: "button", class: "secondary", text: "رفض" }); reject.addEventListener("click", () => reviewParentRequest(r.id, "reject"));
        actions.append(approve, reject); row.append(main, actions); host.append(row);
      });
    } catch (error) { host.replaceChildren(node("p", { class: "hint", text: error.message })); }
  };
  async function reviewParentRequest(id, action) {
    if (!confirm(action === "approve" ? "اعتماد ربط ولي الأمر بهذا الطالب؟" : "رفض طلب الربط؟")) return;
    try { await request(`/api/admin/parent-link-requests/${Number(id)}/${action}`, "POST", {}); await loadParentRequests(); message("تمت مراجعة طلب الربط."); }
    catch (error) { message(error.message, "err"); }
  }

  window.loadAds = async () => {
    const host = el("adsList"); host.replaceChildren(node("p", { class: "hint", text: "جارٍ تحميل الإعلانات..." }));
    try {
      const data = await request("/api/admin/ads"); host.replaceChildren();
      if (!data.ads?.length) return host.append(node("p", { class: "hint", text: "لا توجد إعلانات بعد." }));
      data.ads.forEach((ad) => {
        const row = node("div", { class: "zmz-row" }); const main = node("div", { class: "zmz-row-main" });
        main.append(node("strong", { text: ad.title }), node("small", { text: `${ad.placement} · ${ad.audience} · المشاهدات ${ad.impressions} · النقرات ${ad.clicks} · ${ad.is_active ? "نشط" : "متوقف"}` }));
        const toggle = node("button", { type: "button", class: ad.is_active ? "secondary" : "", text: ad.is_active ? "إيقاف" : "تفعيل" });
        toggle.addEventListener("click", async () => { try { await request(`/api/admin/ads/${ad.id}`, "PATCH", { is_active: !ad.is_active }); await loadAds(); } catch (error) { message(error.message, "err"); } });
        row.append(main, node("div", { class: "zmz-row-actions" })); row.lastChild.append(toggle); host.append(row);
      });
    } catch (error) { host.replaceChildren(node("p", { class: "hint", text: error.message })); }
  };
  window.createAd = async () => {
    const payload = {
      title: el("adTitle").value, body: el("adBody").value, placement: el("adPlacement").value, audience: el("adAudience").value,
      priority: Number(el("adPriority").value), button_text: el("adButton").value, image_url: el("adImage").value, target_url: el("adUrl").value,
      starts_at: el("adStart").value ? new Date(el("adStart").value).toISOString() : null,
      ends_at: el("adEnd").value ? new Date(el("adEnd").value).toISOString() : null,
    };
    try { await request("/api/admin/ads", "POST", payload); ["adTitle", "adBody", "adButton", "adImage", "adUrl", "adStart", "adEnd"].forEach((id) => el(id).value = ""); await loadAds(); message("تم إنشاء الإعلان."); }
    catch (error) { message(error.message, "err"); }
  };

  window.loadNotifications = async () => {
    try {
      const data = await request("/api/admin/notifications"); const host = el("notificationsList"); host.replaceChildren();
      (data.notifications || []).forEach((n) => { const row = node("div", { class: "zmz-row" }); const main = node("div", { class: "zmz-row-main" }); main.append(node("strong", { text: n.title }), node("small", { text: `${n.target_type} · المستلمون ${n.recipient_count} · ${n.scheduled_at}` })); row.append(main); host.append(row); });
    } catch (error) { el("notificationsList").replaceChildren(node("p", { class: "hint", text: error.message })); }
  };
  window.createNotification = async () => {
    const target = el("noticeTarget").value;
    const payload = { title: el("noticeTitle").value, body: el("noticeBody").value, target_type: target, target_value: el("noticeTargetValue").value, is_important: el("noticeImportant").checked, scheduled_at: el("noticeSchedule").value ? new Date(el("noticeSchedule").value).toISOString() : null };
    try { const result = await request("/api/admin/notifications", "POST", payload); message(`تم حفظ الإشعار. عدد المستلمين: ${result.recipient_count}`); el("noticeTitle").value = ""; el("noticeBody").value = ""; await loadNotifications(); }
    catch (error) { message(error.message, "err"); }
  };

  window.loadAnalytics = async () => {
    const host = el("analyticsStats"); host.replaceChildren(node("p", { class: "hint", text: "جارٍ إنشاء التقرير..." }));
    try {
      const data = await request("/api/admin/analytics"); host.replaceChildren();
      const labels = { students: "إجمالي الطلاب", new_students_30d: "تسجيلات آخر 30 يومًا", active_sessions: "الجلسات النشطة", pending_orders: "الطلبات المعلقة", completed_orders: "الطلبات المكتملة", revenue_egp: "الإيراد بالجنيه", materials: "المحتويات", pending_devices: "طلبات الأجهزة", active_ads: "الإعلانات النشطة" };
      Object.entries(labels).forEach(([key, label]) => { const card = node("div", { class: "zmz-stat" }); card.append(node("span", { text: label }), node("strong", { text: Number(data.stats?.[key] || 0).toLocaleString("ar-EG") })); host.append(card); });
    } catch (error) { host.replaceChildren(node("p", { class: "hint", text: error.message })); }
  };
  window.loadAuditLogs = async () => {
    const host = el("auditLogsList"); host.replaceChildren(node("p", { class: "hint", text: "جارٍ تحميل السجل..." }));
    try { const data = await request("/api/admin/audit-logs"); host.replaceChildren(); (data.logs || []).forEach((log) => { const row = node("div", { class: "zmz-row" }); const main = node("div", { class: "zmz-row-main" }); main.append(node("strong", { text: `${log.action} — ${log.entity_type || ""} ${log.entity_id || ""}` }), node("small", { text: `${log.actor_type} #${log.actor_id || "-"} · ${log.created_at} · ${log.ip_address || ""}` })); row.append(main); host.append(row); }); }
    catch (error) { host.replaceChildren(node("p", { class: "hint", text: error.message })); }
  };
  window.loadAdminRoles = async () => {
    const host = el("adminRolesList"); host.replaceChildren(node("p", { class: "hint", text: "جارٍ تحميل الصلاحيات..." }));
    try { const data = await request("/api/admin/roles"); host.replaceChildren(); (data.admins || []).forEach((admin) => { const row = node("div", { class: "zmz-row" }); const main = node("div", { class: "zmz-row-main" }); main.append(node("strong", { text: `${admin.username} (#${admin.id})` })); const select = node("select"); (data.available_roles || []).forEach((role) => select.append(node("option", { value: role, text: role }))); select.value = admin.role; const save = node("button", { type: "button", text: "حفظ الدور" }); save.addEventListener("click", async () => { try { await request(`/api/admin/roles/${admin.id}`, "PUT", { role: select.value }); message("تم تحديث الدور."); } catch (error) { message(error.message, "err"); } }); const actions = node("div", { class: "zmz-row-actions" }); actions.append(select, save); row.append(main, actions); host.append(row); }); }
    catch (error) { host.replaceChildren(node("p", { class: "hint", text: error.message })); }
  };

  window.generateAIContentDraft = async () => {
    const status = el("aiContentStatus"); status.textContent = "جارٍ إنشاء المسودة عبر مزود AI...";
    try {
      const data = await request("/api/admin/ai/content", "POST", { content_type: el("aiContentType").value, title: el("aiContentTitle").value, prompt: el("aiContentPrompt").value });
      status.textContent = data.message || "تم حفظ المسودة للمراجعة."; el("aiContentTitle").value = ""; el("aiContentPrompt").value = "";
      await loadAIContentDrafts();
    } catch (error) { status.textContent = error.message; }
  };
  window.loadAIContentDrafts = async () => {
    const host = el("aiContentDraftList"); host.replaceChildren(node("p", { class: "hint", text: "جارٍ تحميل المسودات..." }));
    try {
      const data = await request("/api/admin/ai/content"); host.replaceChildren();
      if (!data.drafts?.length) return host.append(node("p", { class: "hint", text: "لا توجد مسودات محتوى حتى الآن." }));
      data.drafts.forEach((draft) => {
        const details = node("details", { class: "zmz-row" }); const summary = node("summary", { text: `${draft.title} · ${draft.content_type} · ${draft.status} · ${draft.created_at}` });
        const body = node("pre", { class: "zmz-ai-output", text: draft.content }); details.append(summary, body);
        if (draft.status === "pending_review") {
          const actions = node("div", { class: "zmz-row-actions" });
          const approve = node("button", { type: "button", text: "اعتماد داخلي" });
          approve.addEventListener("click", async () => { try { await request(`/api/admin/ai/content/${draft.id}/review`, "POST", { action: "approve" }); await loadAIContentDrafts(); message("تم اعتماد المسودة داخليًا دون نشرها."); } catch (e) { message(e.message, "err"); } });
          const reject = node("button", { type: "button", class: "secondary", text: "رفض" });
          reject.addEventListener("click", async () => { if (!confirm("رفض مسودة المحتوى؟")) return; try { await request(`/api/admin/ai/content/${draft.id}/review`, "POST", { action: "reject" }); await loadAIContentDrafts(); } catch (e) { message(e.message, "err"); } });
          actions.append(approve, reject); details.append(actions);
        }
        host.append(details);
      });
    } catch (error) { host.replaceChildren(node("p", { class: "hint", text: error.message })); }
  };

  window.runAdminAI = async () => {
    const result = el("adminAiResult"); result.textContent = "جارٍ الاتصال بخدمة الذكاء الاصطناعي...";
    try {
      const data = await request("/api/admin/ai/command", "POST", { mode: el("adminAiMode").value, prompt: el("adminAiPrompt").value });
      result.textContent = data.answer || "لم تصل نتيجة.";
      aiBuilderSuggestion = null;
      if (el("adminAiMode").value === "builder") {
        try { aiBuilderSuggestion = JSON.parse(data.answer); } catch { aiBuilderSuggestion = null; }
      }
    } catch (error) { result.textContent = error.message; }
  };
  window.applyAIBuilderSuggestion = () => {
    if (!aiBuilderSuggestion || !Array.isArray(aiBuilderSuggestion.blocks)) return message("لا يوجد اقتراح JSON صالح. اختر وضع اقتراح مكونات الصفحة ثم أنشئ اقتراحًا جديدًا.", "err");
    const types = new Set(Object.keys(typeNames));
    const blocks = aiBuilderSuggestion.blocks.slice(0, 60).filter((b) => b && types.has(b.type)).map((b) => ({
      id: idValue(), type: b.type, visible: true,
      content: { title: safeText(b.content?.title, 180), text: safeText(b.content?.text, 3000), buttonText: safeText(b.content?.buttonText, 80), href: safeText(b.content?.href, 1000), src: safeText(b.content?.src, 1000), alt: safeText(b.content?.alt, 180) },
      style: { padding: 14, radius: 14, align: "right" }, responsive: {}
    }));
    if (aiBuilderSuggestion.title) el("builderTitle").value = safeText(aiBuilderSuggestion.title, 120);
    builderDoc = { version: 1, blocks };
    loadedBuilderSlug = "";
    renderBuilderBlocks();
    showAdminPage("builder");
    setStatus("اقتراح AI محمّل محليًا. راجعه وعدّله ثم احفظه كمسودة قبل أي نشر.");
  };

  window.loadMedia = async () => {
    const host = el("mediaList"); if (!host) return;
    host.replaceChildren(node("p", { class: "hint", text: "جارٍ تحميل مكتبة الوسائط..." }));
    try {
      const data = await request("/api/admin/media"); host.replaceChildren();
      if (!data.media?.length) { host.append(node("p", { class: "hint", text: "المكتبة فارغة. ارفع أول ملف من النموذج أعلاه." })); return; }
      (data.media || []).forEach((asset) => {
        const card = node("article", { class: "zmz-row media-asset" });
        const main = node("div", { class: "zmz-row-main" });
        main.append(node("strong", { text: asset.file_name }), node("small", { text: `${asset.content_type} · ${(Number(asset.size_bytes || 0) / 1024).toFixed(1)} KB · ${asset.folder} · ${asset.is_public ? "عام" : "خاص"}` }));
        if (asset.content_type?.startsWith("image/") && asset.is_public) {
          const preview = node("img", { src: `${API}/api/media/${asset.id}`, alt: asset.alt_text || "", loading: "lazy" });
          preview.style.cssText = "max-width:150px;max-height:100px;object-fit:contain;border-radius:10px;margin-top:8px"; main.append(preview);
        }
        const alt = node("input", { type: "text", maxlength: "240", placeholder: "الوصف البديل" }); alt.value = asset.alt_text || "";
        const folder = node("input", { type: "text", maxlength: "80", placeholder: "التصنيف" }); folder.value = asset.folder || "general";
        const actions = node("div", { class: "zmz-row-actions" });
        const save = node("button", { type: "button", class: "secondary", text: "حفظ الوصف والتصنيف" });
        save.addEventListener("click", async () => { try { await request(`/api/admin/media/${asset.id}`, "PATCH", { alt_text: alt.value, folder: folder.value }); message("تم تحديث بيانات الوسيط."); await loadMedia(); } catch (e) { message(e.message, "err"); } });
        actions.append(save);
        if (asset.content_type?.startsWith("image/")) {
          const publicLabel = node("label", { class: "check" }); const togglePublic = node("input", { type: "checkbox" }); togglePublic.checked = Boolean(asset.is_public);
          togglePublic.addEventListener("change", async () => { try { await request(`/api/admin/media/${asset.id}`, "PATCH", { is_public: togglePublic.checked }); await loadMedia(); } catch (e) { togglePublic.checked = !togglePublic.checked; message(e.message, "err"); } });
          publicLabel.append(togglePublic, document.createTextNode(" رابط عام")); actions.append(publicLabel);
          const copy = node("button", { type: "button", class: "secondary", text: "نسخ رابط الصورة" }); copy.disabled = !asset.is_public;
          copy.addEventListener("click", () => { const url = `${API}/api/media/${asset.id}`; if (navigator.clipboard?.writeText) navigator.clipboard.writeText(url).then(() => message("تم نسخ رابط الصورة.")).catch(() => message(url)); else message(url); }); actions.append(copy);
        }
        const remove = node("button", { type: "button", class: "danger", text: "حذف الملف" });
        remove.addEventListener("click", async () => { if (!confirm("حذف الملف من المكتبة والتخزين؟ لن يسمح الخادم بحذف ملف مرتبط بمحتوى أو صفحة.")) return; try { await request(`/api/admin/media/${asset.id}`, "DELETE"); await loadMedia(); message("تم حذف الوسيط."); } catch (e) { message(e.message, "err"); } });
        actions.append(remove);
        card.append(main, alt, folder, actions); host.append(card);
      });
    } catch (error) { host.replaceChildren(node("p", { class: "hint", text: error.message })); }
  };

  window.uploadMedia = async () => {
    const file = el("mediaFile")?.files?.[0];
    if (!file) return message("اختر ملفًا أولًا.", "err");
    if (file.size < 1 || file.size > 8 * 1024 * 1024) return message("حجم الملف يجب ألا يتجاوز 8 ميجابايت.", "err");
    const form = new FormData(); form.append("file", file); form.append("folder", el("mediaFolder").value); form.append("alt_text", el("mediaAlt").value); form.append("is_public", el("mediaPublic").checked ? "true" : "false");
    el("mediaStatus").textContent = "جارٍ رفع الملف والتحقق من نوعه...";
    try {
      const response = await fetch(`${API}/api/admin/media/upload`, { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: form });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.success) throw new Error(data.error || "فشل رفع الملف.");
      el("mediaFile").value = ""; el("mediaAlt").value = ""; el("mediaStatus").textContent = `تم رفع ${data.file_name} بنجاح.`;
      await loadMedia(); message("تم رفع الملف إلى مكتبة الوسائط.");
    } catch (error) { el("mediaStatus").textContent = error.message; message(error.message, "err"); }
  };

  function addPageNav() {
    Object.assign(ADMIN_PAGE_META, {
      builder: ["محرر الصفحات", "إنشاء صفحات آمنة وإدارة المسودات والإصدارات والنشر"],
      media: ["مكتبة الوسائط", "رفع الصور والملفات وتنظيمها والتحكم في الروابط العامة"],
      parents: ["أولياء الأمور", "مراجعة طلبات الربط وعرض حسابات أولياء الأمور"],
      ads: ["مركز الإعلانات", "إنشاء الإعلانات وجدولتها ومتابعة المشاهدات والنقرات"],
      notifications: ["الإشعارات", "إنشاء الإشعارات وتوجيهها إلى الجمهور المستهدف"],
      analytics: ["التقارير وسجل التدقيق", "مؤشرات الأداء وسجل العمليات الإدارية"],
      ai: ["مساعد الذكاء الاصطناعي", "اقتراحات الإدارة ومكونات الصفحات بشكل آمن"],
      roles: ["الأدوار والصلاحيات", "تعيين الأدوار للمستخدمين الإداريين"],
      quizzes: ["الاختبارات", "إعداد الاختبارات ونشرها ومراجعة المحاولات والنتائج"],
    });
    const original = window.showAdminPage;
    window.showAdminPage = (page) => {
      original(page);
      if (page === "builder" && !loadedBuilderSlug) builderLoad();
      if (page === "media") loadMedia();
      if (page === "parents") loadParentRequests();
      if (page === "ads") loadAds();
      if (page === "notifications") loadNotifications();
      if (page === "analytics") { loadAnalytics(); loadAuditLogs(); }
      if (page === "roles") loadAdminRoles();
      if (page === "quizzes") { renderQuizQuestionDrafts(); loadQuizzes(); }
      if (page === "ai") loadAIContentDrafts();
    };
    el("builderDevice")?.addEventListener("change", renderBuilderBlocks);
    el("quizQuestionType")?.addEventListener("change", () => {
      const type = el("quizQuestionType").value;
      el("quizChoiceFields").hidden = type !== "mcq";
      el("quizBooleanFields").hidden = type !== "true_false";
    });
    el("builderTitle")?.addEventListener("input", renderBuilderPreview);
    el("builderSlug")?.addEventListener("change", () => { loadedBuilderSlug = ""; });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", addPageNav, { once: true });
  else addPageNav();
})();
