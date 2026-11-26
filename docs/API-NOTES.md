# ملاحظات API المضافة

## Public
- `GET /api/public/settings`
- `GET /api/public/ads?placement=home`
- `POST /api/public/ads/:id/view|click`
- `GET /api/public/pages/:key`

## Parent
- `POST /api/parent/register`
- `POST /api/parent/login`
- `GET /api/parent/me`
- `POST /api/parent/logout`
- `GET /api/parent/children`
- `POST /api/parent/link-request`
- `GET /api/parent/children/:studentId/overview`

## Student Platform
- `GET/PUT /api/student/preferences`
- `GET /api/student/platform/notifications`
- `POST /api/student/platform/notifications/:id/read`
- `GET /api/student/platform/exams`
- `POST /api/student/platform/exams/:id/start`
- `POST /api/student/platform/exam-attempts/:id/submit`
- `POST /api/student/platform/ai`

## Admin Platform
- `GET /api/admin/platform/me`
- `GET/PUT /api/admin/platform/settings`
- `GET /api/admin/platform/dashboard`
- `GET /api/admin/platform/audit`
- `GET/PUT/POST /api/admin/platform/pages...`
- `CRUD /api/admin/platform/ads`
- `GET/POST /api/admin/platform/notifications`
- `GET /api/admin/platform/parents`
- `GET/PUT /api/admin/platform/parent-links/:id`
- `CRUD /api/admin/platform/exams` and questions
- `GET /api/admin/platform/analytics`
- `POST /api/admin/platform/ai`
