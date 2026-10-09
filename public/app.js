const menuButton = document.querySelector('.menu-toggle');
const navigation = document.querySelector('.main-nav');
const root = document.querySelector('#account-root');
const accountActions = document.querySelector('#account-actions');
const authDialog = document.querySelector('#auth-dialog');
const authForm = document.querySelector('#auth-form');
const authFields = document.querySelector('#auth-fields');
const authMessage = document.querySelector('#auth-message');
const authTitle = document.querySelector('#auth-title');
const authIntro = document.querySelector('#auth-intro');
const authSubmit = authForm.querySelector('.form-submit');
const authSwitch = document.querySelector('#auth-switch');

let csrfToken = '';
let authMode = 'login';

const escapeHtml = (value = '') => String(value).replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[char]));

function russianPlural(value, forms) {
  const number = Math.abs(Number(value)) % 100;
  const last = number % 10;
  if (number > 10 && number < 20) return forms[2];
  if (last === 1) return forms[0];
  if (last > 1 && last < 5) return forms[1];
  return forms[2];
}

async function api(path, options = {}) {
  const headers = { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers };
  if (!['GET', 'HEAD'].includes(options.method || 'GET') && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  let response;
  try {
    response = await fetch(path, { credentials: 'same-origin', ...options, headers });
  } catch {
    throw new Error('Не удалось связаться с сервером. Откройте сайт через запущенный backend по адресу http://127.0.0.1:8000, а не как файл или GitHub Pages.');
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 404 && !response.headers.get('content-type')?.includes('application/json')) {
      throw new Error('Сайт открыт без backend API. Для работы регистрации запустите сервер и откройте http://127.0.0.1:8000.');
    }
    if (response.status === 401) {
      currentUser = null;
      renderSignedOut();
    }
    throw new Error(data.error || 'Не удалось выполнить действие. Попробуйте ещё раз.');
  }
  return data;
}

let currentUser = null;

function openAuth(mode = 'login') {
  setAuthMode(mode);
  if (!authDialog.open) authDialog.showModal();
}

function setAuthMode(mode) {
  authMode = mode;
  authMessage.textContent = '';
  const registering = mode === 'register';
  authTitle.textContent = registering ? 'Создать аккаунт' : 'Вход в кабинет';
  authIntro.textContent = registering
    ? 'Зарегистрируйтесь в кабинете ИН МЭИ. Пароль должен содержать не менее 12 символов. Подтверждение номера по СМС пока не подключено — используйте тестовые данные.'
    : 'Введите телефон и пароль.';
  authSubmit.innerHTML = registering ? 'Создать аккаунт <span aria-hidden="true">→</span>' : 'Войти <span aria-hidden="true">→</span>';
  authSwitch.textContent = registering ? 'Уже есть аккаунт? Войти' : 'Ещё нет аккаунта? Зарегистрироваться';
  authFields.innerHTML = `${registering ? `
    <label>Фамилия и имя<input name="name" autocomplete="name" minlength="2" maxlength="120" required></label>
    <label>Учебная группа<input name="group" autocomplete="organization-title" maxlength="80" required></label>
    <label>Опыт наставничества<select name="experience"><option value="junior">Начинающий наставник</option><option value="experienced">Есть опыт наставничества</option></select></label>` : ''}
    <label>Телефон<input name="phone" type="tel" autocomplete="tel" inputmode="tel" maxlength="24" placeholder="+7 900 000-00-00" required></label>
    <label>Пароль<input name="password" type="password" autocomplete="${registering ? 'new-password' : 'current-password'}" minlength="${registering ? '12' : '1'}" maxlength="128" required></label>
    ${registering ? `<label class="consent-line"><input name="consent" type="checkbox" required><span>Согласен(на) на обработку имени, телефона, учебной группы и сведений об опыте для регистрации и организации отбора. <a href="/privacy.html" target="_blank" rel="noopener noreferrer">Как используются данные</a>. Доступ есть у уполномоченных сотрудников ИН МЭИ.</span></label>` : ''}`;
}

function renderSignedOut() {
  accountActions.innerHTML = `<button class="button button-outline" type="button" data-auth-open="login">Войти</button><button class="button button-primary" type="button" data-auth-open="register">Регистрация</button>`;
  root.innerHTML = `<div class="account-welcome"><div><span class="welcome-mark">✳</span><h3>Личный кабинет ИН МЭИ</h3><p>Зарегистрируйтесь, чтобы сохранить профиль, видеть расписание и новости программы. Создание аккаунта не отправляет заявку автоматически.</p></div><button class="button button-primary" type="button" data-auth-open="register">Создать аккаунт <span aria-hidden="true">→</span></button></div><p class="privacy-note">Не передавайте пароль другим людям. Восстановление пароля пока выполняет администратор после проверки личности.</p>`;
}

function statusPill(status, label) {
  const css = status === 'Accepted' ? 'pill-success' : status === 'Rejected' ? 'pill-muted' : 'pill-blue';
  return `<span class="status-pill ${css}">${escapeHtml(label || status)}</span>`;
}

function renderNotifications(items) {
  if (!items.length) return `<div class="empty-state">Уведомлений пока нет.</div>`;
  return `<div class="notice-list">${items.map((notice) => `<article class="notice-item"><span class="notice-dot"></span><div><p>${escapeHtml(notice.message)}</p><time>${escapeHtml(notice.created_at.replace('T', ' ').slice(0, 16))}</time></div></article>`).join('')}</div>`;
}

function renderMaterials(items) {
  if (!items.length) return `<div class="empty-state">Материалы появятся здесь после публикации администратором.</div>`;
  return `<div class="material-list">${items.map((item) => `<article class="material-card"><span class="event-tag">МАТЕРИАЛ ИН МЭИ</span><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.body).replace(/\n/g, '<br>')}</p></article>`).join('')}</div>`;
}

function renderUpcomingEvents(events) {
  if (!events.length) return `<div class="empty-state">Новых событий пока нет.</div>`;
  return `<div class="slot-grid">${events.map((item) => `<article class="slot-card"><div><span class="event-tag">СОБЫТИЕ ИН МЭИ</span><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.display_time)} · ${escapeHtml(item.location)}</p><small>${Number(item.remaining)} ${russianPlural(item.remaining, ['свободное место','свободных места','свободных мест'])}</small></div>${item.booked ? `<span class="status-pill pill-success">Вы записаны</span>` : `<button class="button button-primary" type="button" data-event-book="${escapeHtml(item.id)}" ${Number(item.remaining) < 1 ? 'disabled' : ''}>Записаться</button>`}</article>`).join('')}</div>`;
}

function renderSlots(slots) {
  if (!slots.length) return `<div class="empty-state">Сейчас нет открытых интервалов. Загляните позже: новые даты появятся здесь.</div>`;
  return `<div class="slot-grid">${slots.map((slot) => `<article class="slot-card"><div><span class="event-tag">${slot.kind === 'attestation' ? 'АТТЕСТАЦИЯ' : 'ИНТЕРВЬЮ'}</span><h4>${escapeHtml(slot.display_time)}</h4><p>${escapeHtml(slot.location)}</p><small>${Number(slot.remaining)} ${russianPlural(slot.remaining, ['место','места','мест'])}${slot.interviewer ? ` · ${escapeHtml(slot.interviewer)}` : ''}</small></div><button type="button" class="button button-primary" data-book="${escapeHtml(slot.id)}">Записаться <span aria-hidden="true">→</span></button></article>`).join('')}</div>`;
}

function renderCandidate(dashboard, slots) {
  const user = dashboard.user;
  const bookingCards = dashboard.bookings.length ? dashboard.bookings.map((booking) => `<article class="booking-card"><div><span class="event-tag">ВАШЕ ИНТЕРВЬЮ</span><h4>${escapeHtml(booking.display_time)}</h4><p>${escapeHtml(booking.location)}${booking.interviewer ? ` · ${escapeHtml(booking.interviewer)}` : ''}</p>${booking.result ? `<p class="booking-result">Результат: ${escapeHtml(booking.result)}</p>` : ''}</div><button class="button button-outline button-cancel" data-cancel="${escapeHtml(booking.booking_id)}" type="button">Отменить запись</button></article>`).join('') : `<div class="empty-state">Вы ещё не записаны на интервью. Выберите свободное время ниже.</div>`;
  const myEvents = dashboard.my_events.length ? dashboard.my_events.map((item) => `<article class="booking-card"><div><span class="event-tag">${item.booking_status === 'attended' ? 'ПОСЕЩЕНО' : item.booking_status === 'absent' ? 'НЕ ПОСЕЩЕНО' : 'ВАШЕ СОБЫТИЕ'}</span><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.display_time)} · ${escapeHtml(item.location)}</p></div>${item.booking_status === 'active' ? `<button class="button button-outline button-cancel" data-cancel-event="${escapeHtml(item.booking_id)}" type="button">Отменить запись</button>` : ''}</article>`).join('') : `<div class="empty-state">Вы ещё не записаны на мероприятия.</div>`;
  root.innerHTML = `<div class="dashboard-top"><article class="identity-card"><span class="eyebrow">ВАША ЗАЯВКА</span><h3>${escapeHtml(user.name)}</h3><p>${escapeHtml(user.group || 'Учебная группа не указана')} · ${user.experience === 'experienced' ? 'Опытный наставник' : 'Начинающий наставник'}</p><div>${statusPill(user.status, user.status_label)}</div><button class="text-button" type="button" data-profile-toggle>Редактировать профиль <span aria-hidden="true">↗</span></button></article><article class="identity-aside"><span class="aside-icon">◎</span><h3>Следующий шаг</h3><p>${dashboard.bookings.length ? 'Подготовьтесь к встрече и следите за обновлениями в уведомлениях.' : 'Выберите свободное время для знакомства с командой ИН МЭИ.'}</p></article></div>
  <div class="dashboard-columns"><div class="dashboard-main"><section class="dashboard-panel" id="profile-panel"><div class="panel-heading"><div><span class="event-tag">ВАШИ ДАННЫЕ</span><h3>Профиль кандидата</h3></div><button class="text-button" type="button" data-profile-toggle>Изменить</button></div><form class="profile-form" id="profile-form"><label>Фамилия и имя<input name="name" maxlength="120" required value="${escapeHtml(user.name)}"></label><label>Учебная группа<input name="group" maxlength="80" required value="${escapeHtml(user.group)}"></label><label>Опыт<select name="experience"><option value="junior" ${user.experience === 'junior' ? 'selected' : ''}>Начинающий наставник</option><option value="experienced" ${user.experience === 'experienced' ? 'selected' : ''}>Опытный наставник</option></select></label><label>Страница ВКонтакте<input name="vk_url" type="url" placeholder="https://vk.com/имя" value="${escapeHtml(user.vk_url)}"></label><button class="button button-primary" type="submit">Сохранить профиль <span aria-hidden="true">→</span></button><span class="inline-message" role="status"></span></form></section>
  <section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">РАСПИСАНИЕ</span><h3>Моё интервью</h3></div></div>${bookingCards}</section>
  <section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">ВЫБЕРИТЕ ВРЕМЯ</span><h3>Свободные интервалы</h3></div><button class="text-button" type="button" data-refresh-slots>Обновить ↻</button></div>${renderSlots(slots)}</section>
  <section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">ПРОГРАММА</span><h3>Ближайшие мероприятия</h3></div></div>${renderUpcomingEvents(dashboard.upcoming_events)}</section>
  <section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">МОЙ КАЛЕНДАРЬ</span><h3>Мои мероприятия</h3></div></div>${myEvents}</section></div>
  <aside class="dashboard-aside"><section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">ОБНОВЛЕНИЯ</span><h3>Уведомления</h3></div></div>${renderNotifications(dashboard.notifications)}</section><section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">ПОЛЕЗНОЕ</span><h3>Материалы</h3></div></div>${renderMaterials(dashboard.materials)}</section></aside></div>
  <div class="dashboard-bottom"><span>РОЛЬ: ${escapeHtml(user.role_label.toUpperCase())}</span><span>Телефон: ${escapeHtml(user.phone)}</span><button class="text-button" type="button" data-logout>Выйти из кабинета</button></div>`;
}

function renderAdmin(overview, user) {
  const statusOptions = [['Submitted', 'Заявка отправлена'], ['Interview', 'Интервью'], ['School', 'Школа ИН'], ['Attestation', 'Аттестация'], ['Accepted', 'Наставник'], ['Rejected', 'Отказ']];
  const roleOptions = [['candidate', 'Кандидат'], ['mentor', 'Наставник'], ['interviewer', 'Интервьюер']];
  const people = overview.applicants.length ? overview.applicants.map((person) => `<article class="manage-card"><div class="manage-person"><h4>${escapeHtml(person.full_name)}</h4><p>${escapeHtml(person.phone)} · ${escapeHtml(person.study_group)}</p><span class="event-tag">${person.experience === 'experienced' ? 'ОПЫТНЫЙ НАСТАВНИК' : 'НАЧИНАЮЩИЙ'}</span></div><label>Статус<select data-status-user="${escapeHtml(person.id)}">${statusOptions.map(([value,label]) => `<option value="${value}" ${person.status === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label><label>Роль<select data-role-user="${escapeHtml(person.id)}">${roleOptions.map(([value,label]) => `<option value="${value}" ${person.role === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label></article>`).join('') : `<div class="empty-state">Заявок пока нет.</div>`;
  const slots = overview.slots.length ? overview.slots.map((slot) => `<article class="admin-slot"><div><span class="event-tag">${slot.kind === 'attestation' ? 'АТТЕСТАЦИЯ' : 'ИНТЕРВЬЮ'} · ${slot.status === 'open' ? 'ОТКРЫТ' : 'ОТМЕНЁН'}</span><h4>${escapeHtml(slot.display_time)}</h4><p>${escapeHtml(slot.location)} · ${Number(slot.booked)} из ${Number(slot.capacity)} мест</p><small>${slot.interviewer ? `Интервьюер: ${escapeHtml(slot.interviewer)}` : 'Интервьюер не назначен'}</small></div>${slot.status === 'open' ? `<button type="button" class="text-button danger-text" data-cancel-slot="${escapeHtml(slot.id)}">Отменить интервал</button>` : ''}</article>`).join('') : `<div class="empty-state">Создайте первый интервал интервью.</div>`;
  const reviews = (overview.reviews || []).length ? overview.reviews.map((booking) => `<article class="review-card"><div><h4>${escapeHtml(booking.full_name)}</h4><p>${escapeHtml(booking.display_time)} · ${escapeHtml(booking.study_group)}</p>${booking.result ? `<p>Результат: ${escapeHtml(booking.result)}${booking.grade ? ` · оценка ${Number(booking.grade)}/10` : ''}</p>` : ''}</div><form class="review-form" data-review="${escapeHtml(booking.id)}"><label>Итог интервью<textarea name="result" maxlength="1000" required placeholder="Кратко зафиксируйте результат">${escapeHtml(booking.result)}</textarea></label>${user.role === 'admin' ? `<label>Оценка<input name="grade" type="number" min="1" max="10" value="${booking.grade ? Number(booking.grade) : ''}"></label>` : ''}<button class="button button-primary" type="submit">Сохранить итог</button><span class="inline-message" role="status"></span></form></article>`).join('') : `<div class="empty-state">Назначенные интервью и результаты появятся здесь.</div>`;
  const interviewers = overview.interviewers.map((x) => `<option value="${escapeHtml(x.id)}">${escapeHtml(x.full_name)} · ${x.role === 'admin' ? 'администратор' : 'интервьюер'}</option>`).join('');
  const statusSummary = [['Submitted','Заявки'],['Interview','Интервью'],['School','Школа ИН'],['Attestation','Аттестация'],['Accepted','Наставники'],['Rejected','Отказ']].map(([key,label]) => `<div><span>${label}</span><strong>${Number(overview.stats.statuses[key] || 0)}</strong></div>`).join('');
  const managedMaterials = overview.materials.map((item) => `<article class="admin-slot content-manage"><div><span class="event-tag">${item.published ? 'ОПУБЛИКОВАН' : 'СКРЫТ'}</span><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.body.slice(0, 180))}${item.body.length > 180 ? '…' : ''}</p></div><div class="content-actions"><button class="text-button" type="button" data-edit-material="${escapeHtml(item.id)}">Изменить</button><button class="text-button" type="button" data-publish-material="${escapeHtml(item.id)}" data-published="${item.published ? 'true' : 'false'}">${item.published ? 'Скрыть' : 'Опубликовать'}</button></div></article>`).join('') || `<div class="empty-state">Материалов пока нет.</div>`;
  const managedEvents = overview.events.map((item) => `<article class="admin-slot content-manage"><div><span class="event-tag">${item.published ? 'ОПУБЛИКОВАНО' : 'СКРЫТО'}</span><h4>${escapeHtml(item.title)}</h4><p>${escapeHtml(item.display_time)} · ${escapeHtml(item.location)} · ${Number(item.booked)} из ${Number(item.capacity)} участников · ${escapeHtml(item.description.slice(0, 140))}</p></div><div class="content-actions"><button class="text-button" type="button" data-edit-event="${escapeHtml(item.id)}">Изменить</button><button class="text-button" type="button" data-publish-event="${escapeHtml(item.id)}" data-published="${item.published ? 'true' : 'false'}">${item.published ? 'Скрыть' : 'Опубликовать'}</button></div></article>`).join('') || `<div class="empty-state">Событий пока нет.</div>`;
  const attendeeStatuses = [['active','Записан'],['attended','Посетил'],['absent','Не пришёл'],['cancelled','Отменил']];
  const attendees = overview.event_attendees.map((item) => `<article class="manage-card event-attendee"><div class="manage-person"><h4>${escapeHtml(item.full_name)}</h4><p>${escapeHtml(item.event_title)} · ${escapeHtml(item.display_time)} · ${escapeHtml(item.study_group)}</p><span class="event-tag">${escapeHtml(item.phone)}</span></div><label>Участие<select data-event-attendance="${escapeHtml(item.id)}">${attendeeStatuses.map(([value,label]) => `<option value="${value}" ${item.status === value ? 'selected' : ''}>${label}</option>`).join('')}</select></label></article>`).join('') || `<div class="empty-state">Записей на мероприятия пока нет.</div>`;
  root.innerHTML = `<div class="admin-welcome"><div><span class="eyebrow">РАБОЧЕЕ МЕСТО · ${escapeHtml(user.role_label.toUpperCase())}</span><h3>Управляйте набором<br>и расписанием.</h3></div><div class="stats-grid"><article><strong>${Number(overview.stats.applicants)}</strong><span>КАНДИДАТОВ</span></article><article><strong>${Number(overview.stats.interviews)}</strong><span>АКТИВНЫХ ЗАПИСЕЙ</span></article><article><strong>${Number(overview.slots.filter((x) => x.status === 'open').length)}</strong><span>ИНТЕРВАЛОВ ОТКРЫТО</span></article></div></div><div class="status-summary">${statusSummary}</div>
  <div class="admin-columns"><div class="admin-main"><section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">ОТБОР</span><h3>Кандидаты</h3></div><button class="text-button" data-refresh-admin type="button">Обновить ↻</button></div><div class="manage-list">${people}</div></section>
  <section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">ИНТЕРВЬЮ</span><h3>Результаты и оценки</h3></div></div><div class="review-list">${reviews}</div></section>
  <section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">РАСПИСАНИЕ</span><h3>Интервью</h3></div></div><div class="admin-slot-list">${slots}</div></section></div>
  <aside class="admin-aside"><section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">НОВЫЕ МЕСТА</span><h3>Создать интервал</h3></div></div><form class="stack-form" id="slot-form"><label>Тип записи<select name="kind"><option value="interview">Интервью</option><option value="attestation">Аттестация</option></select></label><label>Дата и время<input name="starts_at" type="datetime-local" required></label><label>Место проведения<input name="location" maxlength="160" placeholder="Корпус, аудитория" required></label><label>Количество мест<input name="capacity" type="number" min="1" max="100" value="1" required></label><label>Интервьюер<select name="interviewer_id"><option value="">Не назначен</option>${interviewers}</select></label><button class="button button-primary" type="submit">Добавить в расписание <span aria-hidden="true">→</span></button><span class="inline-message" role="status"></span></form></section>
  <section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">НОВОСТИ</span><h3>Материалы</h3></div></div><form class="stack-form" id="material-form"><label>Заголовок<input name="title" maxlength="140" required></label><label>Текст<textarea name="body" maxlength="8000" rows="4" required></textarea></label><button class="button button-outline" type="submit">Опубликовать материал</button><span class="inline-message" role="status"></span></form><div class="content-manager">${managedMaterials}</div></section>
  <section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">КАЛЕНДАРЬ</span><h3>События программы</h3></div></div><form class="stack-form" id="event-form"><label>Название<input name="title" maxlength="140" required></label><label>Описание<textarea name="description" maxlength="2000" rows="3" required></textarea></label><label>Дата и время<input name="starts_at" type="datetime-local" required></label><label>Место<input name="location" maxlength="160"></label><label>Число мест<input name="capacity" type="number" min="1" max="500" value="100" required></label><button class="button button-outline" type="submit">Опубликовать событие</button><span class="inline-message" role="status"></span></form><div class="content-manager">${managedEvents}</div></section>
  <section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">УЧАСТНИКИ</span><h3>Посещение мероприятий</h3></div></div><div class="manage-list">${attendees}</div></section></aside></div>
  <div class="dashboard-bottom"><span>АДМИНИСТРАТИВНЫЙ ДОСТУП ПРОВЕРЕН СЕРВЕРОМ</span><span>${escapeHtml(user.name)}</span><button class="text-button" type="button" data-logout>Выйти из кабинета</button></div>`;
}

function renderInterviewer(overview, user) {
  const reviews = overview.reviews?.length ? overview.reviews.map((booking) => `<article class="review-card"><div><h4>${escapeHtml(booking.full_name)}</h4><p>${escapeHtml(booking.display_time)} · ${escapeHtml(booking.study_group)}</p></div><form class="review-form" data-review="${escapeHtml(booking.id)}"><label>Итог интервью<textarea name="result" maxlength="1000" required placeholder="Кратко зафиксируйте результат">${escapeHtml(booking.result)}</textarea></label><button class="button button-primary" type="submit">Сохранить результат</button><span class="inline-message" role="status"></span></form></article>`).join('') : `<div class="empty-state">У вас пока нет назначенных интервью.</div>`;
  root.innerHTML = `<div class="admin-welcome"><div><span class="eyebrow">РАБОЧЕЕ МЕСТО · ИНТЕРВЬЮЕР</span><h3>Ваши интервью<br>и результаты.</h3></div><div class="stats-grid"><article><strong>${Number(overview.stats.interviews)}</strong><span>КАНДИДАТОВ</span></article></div></div><section class="dashboard-panel"><div class="panel-heading"><div><span class="event-tag">НАЗНАЧЕННЫЕ ВСТРЕЧИ</span><h3>Список интервью</h3></div></div><div class="review-list">${reviews}</div></section><div class="dashboard-bottom"><span>ДАННЫЕ ОЦЕНОК ДОСТУПНЫ УПОЛНОМОЧЕННОМУ АДМИНИСТРАТОРУ</span><span>${escapeHtml(user.name)}</span><button class="text-button" type="button" data-logout>Выйти из кабинета</button></div>`;
}

async function renderWorkspace() {
  if (!currentUser) return renderSignedOut();
  accountActions.innerHTML = `<span class="user-compact">${escapeHtml(currentUser.name)} · ${escapeHtml(currentUser.role_label)}</span>`;
  root.innerHTML = `<div class="loading-card"><span class="loading-dot"></span>Загружаем ваши данные…</div>`;
  try {
    const dashboard = await api('/api/dashboard');
    currentUser = dashboard.user;
    if (currentUser.role === 'admin' || currentUser.role === 'interviewer') {
      const overview = await api('/api/admin/overview');
      const reviews = await api('/api/work').catch(() => null);
      if (reviews) overview.reviews = reviews.reviews;
      if (currentUser.role === 'admin') renderAdmin(overview, currentUser);
      else renderInterviewer(overview, currentUser);
    } else {
      const slotData = await api('/api/slots');
      renderCandidate(dashboard, slotData.slots);
    }
  } catch (error) {
    root.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
  }
}

async function renderPublic() {
  const container = document.querySelector('#public-events');
  try {
    const data = await api('/api/public');
    const cards = data.events.map((event) => `<article class="event-row"><div class="event-date"><strong>${escapeHtml(event.display_time.split(', ')[0].slice(0, 5))}</strong><span>${escapeHtml(event.display_time.split(', ')[1] || '')} · ${escapeHtml(event.display_time.split(', ')[0].slice(-4))}</span></div><div class="event-details"><span class="event-tag">СОБЫТИЕ ИН МЭИ</span><h3>${escapeHtml(event.title)}</h3><p>${escapeHtml(event.description)}${event.location ? ` · ${escapeHtml(event.location)}` : ''} · ${Number(event.remaining)} мест</p></div><button type="button" class="button button-outline event-book-button" data-event-book="${escapeHtml(event.id)}" ${Number(event.remaining) < 1 ? 'disabled' : ''}>Записаться <span aria-hidden="true">→</span></button></article>`).join('');
    container.innerHTML = cards || `<p class="demo-caption">Пока нет опубликованных событий. Следите за обновлениями.</p>`;
  } catch {
    container.innerHTML = `<p class="demo-caption">Не удалось загрузить события. Обновите страницу позже.</p>`;
  }
}

async function bootstrap() {
  try {
    const session = await api('/api/session');
    csrfToken = session.csrf || '';
    currentUser = session.user;
    if (currentUser) await renderWorkspace(); else renderSignedOut();
  } catch {
    root.innerHTML = `<div class="empty-state">Backend API не отвечает. Запустите в папке проекта команду <code>python3 server.py</code> (в Windows — <code>py server.py</code>) и откройте сайт по адресу <code>http://127.0.0.1:8000</code>. GitHub Pages и файл index.html не подключены к базе данных.</div>`;
  }
  await renderPublic();
}

menuButton?.addEventListener('click', () => {
  const expanded = menuButton.getAttribute('aria-expanded') === 'true';
  menuButton.setAttribute('aria-expanded', String(!expanded));
  navigation?.classList.toggle('is-open', !expanded);
});

function selectSectionTab(id) {
  for (const button of navigation?.querySelectorAll('[data-section-tab]') || []) {
    const selected = button.dataset.sectionTab === id;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
  }
  for (const sectionId of ['about', 'path', 'events', 'faq', 'join']) {
    const section = document.getElementById(sectionId);
    if (section) section.hidden = sectionId !== id;
  }
  const quote = document.getElementById('path-quote');
  if (quote) quote.hidden = id !== 'path';
  menuButton?.setAttribute('aria-expanded', 'false');
  navigation?.classList.remove('is-open');
}

navigation?.addEventListener('click', (event) => {
  const button = event.target.closest('[data-section-tab]');
  if (button) selectSectionTab(button.dataset.sectionTab);
});

document.addEventListener('click', async (event) => {
  const target = event.target.closest('[data-auth-open],[data-section-open],[data-auth-close],[data-profile-toggle],[data-book],[data-cancel],[data-cancel-event],[data-event-book],[data-cancel-slot],[data-refresh-slots],[data-refresh-admin],[data-logout],[data-edit-material],[data-publish-material],[data-edit-event],[data-publish-event]');
  if (!target) return;
  if (target.hasAttribute('data-section-open')) selectSectionTab(target.dataset.sectionOpen);
  if (target.hasAttribute('data-auth-open')) { event.preventDefault(); openAuth(target.dataset.authOpen); }
  if (target.hasAttribute('data-auth-close')) authDialog.close();
  if (target.hasAttribute('data-profile-toggle')) document.querySelector('#profile-form')?.classList.toggle('is-editing');
  if (target.hasAttribute('data-refresh-slots') || target.hasAttribute('data-refresh-admin')) await renderWorkspace();
  if (target.hasAttribute('data-book')) {
    target.disabled = true;
    try { await api('/api/bookings', { method: 'POST', body: JSON.stringify({ slot_id: target.dataset.book }) }); await renderWorkspace(); }
    catch (error) { alert(error.message); target.disabled = false; }
  }
  if (target.hasAttribute('data-event-book')) {
    if (!currentUser) { openAuth('register'); return; }
    target.disabled = true;
    try { await api('/api/events/bookings', { method: 'POST', body: JSON.stringify({ event_id: target.dataset.eventBook }) }); await renderWorkspace(); await renderPublic(); }
    catch (error) { alert(error.message); target.disabled = false; }
  }
  if (target.hasAttribute('data-cancel-event')) {
    if (!confirm('Отменить вашу запись на мероприятие?')) return;
    try { await api('/api/events/bookings/cancel', { method: 'POST', body: JSON.stringify({ booking_id: target.dataset.cancelEvent }) }); await renderWorkspace(); await renderPublic(); }
    catch (error) { alert(error.message); }
  }
  if (target.hasAttribute('data-cancel')) {
    if (!confirm('Отменить вашу запись на интервью?')) return;
    try { await api('/api/bookings/cancel', { method: 'POST', body: JSON.stringify({ booking_id: target.dataset.cancel }) }); await renderWorkspace(); }
    catch (error) { alert(error.message); }
  }
  if (target.hasAttribute('data-cancel-slot')) {
    if (!confirm('Отменить интервал? Записанные кандидаты получат уведомления.')) return;
    try { await api(`/api/admin/slots/${encodeURIComponent(target.dataset.cancelSlot)}`, { method: 'POST', body: JSON.stringify({ action: 'cancel' }) }); await renderWorkspace(); }
    catch (error) { alert(error.message); }
  }
  if (target.hasAttribute('data-publish-material') || target.hasAttribute('data-publish-event')) {
    const isMaterial = target.hasAttribute('data-publish-material');
    const type = isMaterial ? 'materials' : 'events';
    const id = isMaterial ? target.dataset.publishMaterial : target.dataset.publishEvent;
    const published = target.dataset.published !== 'true';
    try { await api(`/api/admin/${type}/${encodeURIComponent(id)}`, { method: 'PATCH', body: JSON.stringify({ published }) }); await renderWorkspace(); await renderPublic(); }
    catch (error) { alert(error.message); }
  }
  if (target.hasAttribute('data-edit-material')) {
    try {
      const overview = await api('/api/admin/overview');
      const item = overview.materials.find((x) => x.id === target.dataset.editMaterial);
      if (!item) throw new Error('Материал не найден.');
      const title = prompt('Название материала', item.title);
      if (title === null) return;
      const body = prompt('Текст материала', item.body);
      if (body === null) return;
      await api(`/api/admin/materials/${encodeURIComponent(item.id)}`, { method: 'PATCH', body: JSON.stringify({ title, body }) });
      await renderWorkspace(); await renderPublic();
    } catch (error) { alert(error.message); }
  }
  if (target.hasAttribute('data-edit-event')) {
    try {
      const overview = await api('/api/admin/overview');
      const item = overview.events.find((x) => x.id === target.dataset.editEvent);
      if (!item) throw new Error('Событие не найдено.');
      const title = prompt('Название события', item.title);
      if (title === null) return;
      const description = prompt('Описание события', item.description);
      if (description === null) return;
      const startsAt = new Date(item.starts_at);
      const localStarts = new Intl.DateTimeFormat('sv-SE', { timeZone: 'Europe/Moscow', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(startsAt).replace(' ', 'T');
      const starts_at = prompt('Дата и время (московское, ГГГГ-ММ-ДДTЧЧ:ММ)', localStarts);
      if (starts_at === null) return;
      const location = prompt('Место проведения', item.location);
      if (location === null) return;
      const updates = { title, description, location };
      if (starts_at !== localStarts) updates.starts_at = starts_at;
      await api(`/api/admin/events/${encodeURIComponent(item.id)}`, { method: 'PATCH', body: JSON.stringify(updates) });
      await renderWorkspace(); await renderPublic();
    } catch (error) { alert(error.message); }
  }
  if (target.hasAttribute('data-logout')) {
    try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); currentUser = null; csrfToken = ''; await bootstrap(); }
    catch (error) { alert(error.message); }
  }
});

authSwitch.addEventListener('click', () => setAuthMode(authMode === 'login' ? 'register' : 'login'));
authDialog.addEventListener('click', (event) => { if (event.target === authDialog) authDialog.close(); });
authForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  authMessage.textContent = '';
  const form = new FormData(authForm);
  const body = Object.fromEntries(form.entries());
  if (authMode === 'register') body.consent = form.has('consent');
  authSubmit.disabled = true;
  try {
    const response = await api(`/api/auth/${authMode === 'register' ? 'register' : 'login'}`, { method: 'POST', body: JSON.stringify(body) });
    currentUser = response.user; csrfToken = response.csrf;
    authDialog.close();
    await renderWorkspace();
    document.querySelector('#cabinet').scrollIntoView({ behavior: 'smooth' });
  } catch (error) {
    authMessage.textContent = error.message;
  } finally { authSubmit.disabled = false; }
});

root.addEventListener('submit', async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  event.preventDefault();
  const message = form.querySelector('.inline-message');
  const values = Object.fromEntries(new FormData(form).entries());
  if (form.id === 'profile-form') {
    try { await api('/api/profile', { method: 'PATCH', body: JSON.stringify(values) }); await renderWorkspace(); }
    catch (error) { if (message) message.textContent = error.message; }
  } else if (form.id === 'slot-form') {
    try { await api('/api/admin/slots', { method: 'POST', body: JSON.stringify(values) }); await renderWorkspace(); }
    catch (error) { if (message) message.textContent = error.message; }
  } else if (form.id === 'material-form') {
    try { await api('/api/admin/materials', { method: 'POST', body: JSON.stringify(values) }); await renderWorkspace(); await renderPublic(); }
    catch (error) { if (message) message.textContent = error.message; }
  } else if (form.id === 'event-form') {
    try { await api('/api/admin/events', { method: 'POST', body: JSON.stringify(values) }); await renderWorkspace(); await renderPublic(); }
    catch (error) { if (message) message.textContent = error.message; }
  } else if (form.matches('[data-review]')) {
    try { await api(`/api/admin/bookings/${encodeURIComponent(form.dataset.review)}/result`, { method: 'POST', body: JSON.stringify(values) }); await renderWorkspace(); }
    catch (error) { if (message) message.textContent = error.message; }
  }
});

root.addEventListener('change', async (event) => {
  const select = event.target;
  if (!(select instanceof HTMLSelectElement)) return;
  if (select.dataset.statusUser) {
    try { await api(`/api/admin/users/${encodeURIComponent(select.dataset.statusUser)}/status`, { method: 'POST', body: JSON.stringify({ status: select.value }) }); await renderWorkspace(); }
    catch (error) { alert(error.message); await renderWorkspace(); }
  }
  if (select.dataset.roleUser) {
    try { await api(`/api/admin/users/${encodeURIComponent(select.dataset.roleUser)}/role`, { method: 'POST', body: JSON.stringify({ role: select.value }) }); await renderWorkspace(); }
    catch (error) { alert(error.message); await renderWorkspace(); }
  }
});

bootstrap();
