// server.js - الخادم الرئيسي لمنصة إعمارنا 3
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(cors());

// ─── إعداد Firebase ───────────────────────────────────────
const serviceAccount = require('./serviceAccountKey.json');
if (!admin.apps.length) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}
const db = admin.firestore();

// ─── مسار الاختبار ────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ success: true, message: '✅ خادم إعمارنا 3 يعمل بنجاح!' });
});

// ══════════════════════════════════════════════════════════
//                     المستخدمون
// ══════════════════════════════════════════════════════════

// تسجيل مستخدم جديد
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, organization, phone } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'يرجى ملء جميع الحقول الإلزامية' });
    }

    // التحقق أن البريد غير مستخدم
    const existing = await db.collection('users').where('email', '==', email).get();
    if (!existing.empty) {
      return res.status(400).json({ message: 'البريد الإلكتروني مستخدم بالفعل' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = {
      name, email,
      password: hashedPassword,
      role: role || 'community',
      organization: organization || '',
      phone: phone || '',
      isApproved: role === 'community' || !role,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('users').add(userData);
    res.status(201).json({
      success: true,
      message: role === 'community' ? 'تم إنشاء الحساب بنجاح' : 'تم إنشاء الحساب وينتظر الموافقة',
      userId: docRef.id
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// تسجيل الدخول
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'يرجى إدخال البريد وكلمة المرور' });
    }

    const snapshot = await db.collection('users').where('email', '==', email).limit(1).get();
    if (snapshot.empty) {
      return res.status(404).json({ message: 'البريد الإلكتروني غير مسجل' });
    }

    const userDoc = snapshot.docs[0];
    const user = { id: userDoc.id, ...userDoc.data() };

if (!user.password.startsWith('$2')) {
  if (user.password !== password) {
    return res.status(401).json({ message: 'كلمة المرور غير صحيحة' });
  }
  delete user.password;
  return res.status(200).json({ 
    success: true, 
    message: 'تم تسجيل الدخول بنجاح', 
    token: `token-${userDoc.id}`, 
    user 
  });
}

if (!user.password.startsWith('$2')) {
  if (user.password !== password) {
    return res.status(401).json({ message: 'كلمة المرور غير صحيحة' });
  }
  delete user.password;
  return res.status(200).json({ 
    success: true, 
    message: 'تم تسجيل الدخول بنجاح', 
    token: `token-${userDoc.id}`, 
    user 
  });
}

// الكود التالي (غالباً للتعامل مع Bcrypt) ...
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ message: 'كلمة المرور غير صحيحة' });
    }

    if (!user.isApproved) {
      return res.status(403).json({ message: 'حسابك ينتظر الموافقة من المسؤول' });
    }

    // إزالة كلمة المرور من الرد
    delete user.password;

    res.status(200).json({
      success: true,
      message: 'تم تسجيل الدخول بنجاح',
      token: `token-${userDoc.id}`,
      user: user
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// جلب جميع المستخدمين
app.get('/api/users', async (req, res) => {
  try {
    const snapshot = await db.collection('users').orderBy('createdAt', 'desc').get();
    const users = snapshot.docs.map(doc => {
      const data = doc.data();
      delete data.password;
      return { id: doc.id, ...data };
    });
    res.status(200).json({ success: true, count: users.length, data: users });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// الموافقة على مستخدم
app.patch('/api/users/:id/approve', async (req, res) => {
  try {
    await db.collection('users').doc(req.params.id).update({ isApproved: true });
    res.status(200).json({ success: true, message: 'تمت الموافقة على المستخدم' });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// تعطيل مستخدم
app.patch('/api/users/:id/disable', async (req, res) => {
  try {
    await db.collection('users').doc(req.params.id).update({ isApproved: false });
    res.status(200).json({ success: true, message: 'تم تعطيل المستخدم' });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//                      البلاغات
// ══════════════════════════════════════════════════════════

// إضافة بلاغ جديد
app.post('/api/reports', async (req, res) => {
  try {
    const {
      damageType, district, address, description,
      severity, reporterName, reporterPhone,
      reporterRole, reporterEmail, lat, lng
    } = req.body;

    if (!damageType || !district || !address || !description || !reporterName || !reporterPhone) {
      return res.status(400).json({ message: 'يرجى ملء جميع الحقول الإلزامية' });
    }

    const reportData = {
      damageType, district, address, description,
      severity: severity || 'متوسطة',
      reporterName, reporterPhone,
      reporterRole: reporterRole || 'مواطن',
      reporterEmail: reporterEmail || '',
      location: lat && lng ? { lat: parseFloat(lat), lng: parseFloat(lng) } : null,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('reports').add(reportData);
    res.status(201).json({
      success: true,
      message: 'تم استلام بلاغك بنجاح',
      reportId: docRef.id
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// جلب البلاغات
app.get('/api/reports', async (req, res) => {
  try {
    const { status, district, severity } = req.query;
    let query = db.collection('reports').orderBy('createdAt', 'desc');

    const snapshot = await query.get();
    let reports = snapshot.docs.map(doc => ({
      id: doc.id, ...doc.data(),
      createdAt: doc.data().createdAt?.toDate()?.toISOString() || null
    }));

    if (status) reports = reports.filter(r => r.status === status);
    if (district) reports = reports.filter(r => r.district === district);
    if (severity) reports = reports.filter(r => r.severity === severity);

    res.status(200).json({ success: true, count: reports.length, data: reports });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// إحصائيات البلاغات
app.get('/api/reports/stats/summary', async (req, res) => {
  try {
    const snapshot = await db.collection('reports').get();
    const reports = snapshot.docs.map(d => d.data());

    const stats = {
      total: reports.length,
      pending: reports.filter(r => r.status === 'pending').length,
      reviewing: reports.filter(r => r.status === 'reviewing').length,
      approved: reports.filter(r => r.status === 'approved').length,
      done: reports.filter(r => r.status === 'done').length,
      rejected: reports.filter(r => r.status === 'rejected').length,
      critical: reports.filter(r => r.severity === 'حرجة').length,
    };

    res.status(200).json({ success: true, data: stats });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// تحديث حالة البلاغ
app.patch('/api/reports/:id/status', async (req, res) => {
  try {
    const { status, notes } = req.body;
    await db.collection('reports').doc(req.params.id).update({
      status,
      adminNotes: notes || '',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    res.status(200).json({ success: true, message: 'تم تحديث الحالة' });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// حذف بلاغ
app.delete('/api/reports/:id', async (req, res) => {
  try {
    await db.collection('reports').doc(req.params.id).delete();
    res.status(200).json({ success: true, message: 'تم حذف البلاغ' });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//                      المشاريع
// ══════════════════════════════════════════════════════════

// إضافة مشروع
app.post('/api/projects', async (req, res) => {
  try {
    const { name, sector, organization, district, description, budget, startDate, endDate } = req.body;
    if (!name || !sector || !district) {
      return res.status(400).json({ message: 'يرجى ملء الحقول الإلزامية' });
    }

    const projectData = {
      name, sector,
      organization: organization || '',
      district, description: description || '',
      budget: parseFloat(budget) || 0,
      startDate: startDate || '',
      endDate: endDate || '',
      progress: 0,
      status: 'reviewing',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('projects').add(projectData);
    res.status(201).json({ success: true, message: 'تم إضافة المشروع', id: docRef.id });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// جلب المشاريع
app.get('/api/projects', async (req, res) => {
  try {
    const snapshot = await db.collection('projects').orderBy('createdAt', 'desc').get();
    const projects = snapshot.docs.map(doc => ({
      id: doc.id, ...doc.data(),
      createdAt: doc.data().createdAt?.toDate()?.toISOString() || null
    }));
    res.status(200).json({ success: true, count: projects.length, data: projects });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// إحصائيات المشاريع
app.get('/api/projects/stats/summary', async (req, res) => {
  try {
    const snapshot = await db.collection('projects').get();
    const projects = snapshot.docs.map(d => d.data());

    const stats = {
      total: projects.length,
      reviewing: projects.filter(p => p.status === 'reviewing').length,
      active: projects.filter(p => p.status === 'active').length,
      done: projects.filter(p => p.status === 'done').length,
      totalBudget: projects.reduce((s, p) => s + (p.budget || 0), 0),
      avgProgress: projects.length
        ? Math.round(projects.reduce((s, p) => s + (p.progress || 0), 0) / projects.length)
        : 0
    };

    res.status(200).json({ success: true, data: stats });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// تحديث نسبة الإنجاز
app.patch('/api/projects/:id/progress', async (req, res) => {
  try {
    const { progress, status } = req.body;
    await db.collection('projects').doc(req.params.id).update({
      progress: parseInt(progress) || 0,
      status: status || 'active',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    res.status(200).json({ success: true, message: 'تم تحديث التقدم' });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// تحديث حالة المشروع
app.patch('/api/projects/:id/status', async (req, res) => {
  try {
    await db.collection('projects').doc(req.params.id).update({
      status: req.body.status,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    res.status(200).json({ success: true, message: 'تم تحديث الحالة' });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// ══════════════════════════════════════════════════════════
//                   تقارير المنظمات
// ══════════════════════════════════════════════════════════

// رفع تقرير جديد من منظمة
app.post('/api/org-reports', async (req, res) => {
  try {
    const { projectId, projectName, organizationName, progress, description, challenges, nextSteps, submittedBy } = req.body;
    if (!projectId || !description) {
      return res.status(400).json({ message: 'يرجى ملء الحقول الإلزامية' });
    }

    const reportData = {
      projectId, projectName: projectName || '',
      organizationName: organizationName || '',
      progress: parseInt(progress) || 0,
      description, 
      challenges: challenges || '',
      nextSteps: nextSteps || '',
      submittedBy: submittedBy || '',
      status: 'pending', // pending | approved | rejected
      governmentNotes: '',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    const docRef = await db.collection('orgReports').add(reportData);

    // تحديث نسبة إنجاز المشروع تلقائياً
    await db.collection('projects').doc(projectId).update({
      progress: parseInt(progress) || 0,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }).catch(() => {}); // تجاهل الخطأ إذا المشروع غير موجود

    res.status(201).json({
      success: true,
      message: 'تم رفع التقرير بنجاح وينتظر موافقة الحكومة',
      reportId: docRef.id
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// جلب جميع تقارير المنظمات
app.get('/api/org-reports', async (req, res) => {
  try {
    const { projectId, status, organization } = req.query;
    const snapshot = await db.collection('orgReports').orderBy('createdAt', 'desc').get();
    let reports = snapshot.docs.map(doc => ({
      id: doc.id, ...doc.data(),
      createdAt: doc.data().createdAt?.toDate()?.toISOString() || null
    }));

    if (projectId) reports = reports.filter(r => r.projectId === projectId);
    if (status) reports = reports.filter(r => r.status === status);
    if (organization) reports = reports.filter(r => r.organizationName === organization);

    res.status(200).json({ success: true, count: reports.length, data: reports });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// موافقة الحكومة على تقرير أو رفضه
app.patch('/api/org-reports/:id/review', async (req, res) => {
  try {
    const { status, notes } = req.body;
    if (!['approved', 'rejected'].includes(status)) {
      return res.status(400).json({ message: 'حالة غير صحيحة' });
    }

    const reportDoc = await db.collection('orgReports').doc(req.params.id).get();
    if (!reportDoc.exists) {
      return res.status(404).json({ message: 'التقرير غير موجود' });
    }

    await db.collection('orgReports').doc(req.params.id).update({
      status,
      governmentNotes: notes || '',
      reviewedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // إذا وافقت الحكومة، تحديث حالة المشروع
    if (status === 'approved') {
      const reportData = reportDoc.data();
      const newProgress = reportData.progress || 0;
      await db.collection('projects').doc(reportData.projectId).update({
        progress: newProgress,
        status: newProgress >= 100 ? 'done' : 'active',
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      }).catch(() => {});
    }

    res.status(200).json({
      success: true,
      message: status === 'approved' ? 'تمت الموافقة على التقرير' : 'تم رفض التقرير'
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// إحصائيات تقارير المنظمات
app.get('/api/org-reports/stats', async (req, res) => {
  try {
    const snapshot = await db.collection('orgReports').get();
    const reports = snapshot.docs.map(d => d.data());
    res.status(200).json({
      success: true,
      data: {
        total: reports.length,
        pending: reports.filter(r => r.status === 'pending').length,
        approved: reports.filter(r => r.status === 'approved').length,
        rejected: reports.filter(r => r.status === 'rejected').length,
      }
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});

// ─── تشغيل الخادم ────────────────────────────────────────
const PORT = process.env.port//5000;
app.listen(PORT, () => {
  console.log(`✅ خادم إعمارنا 3 يعمل على المنفذ ${PORT}`);
  console.log(`🌐 http://localhost:${PORT}`);
});
