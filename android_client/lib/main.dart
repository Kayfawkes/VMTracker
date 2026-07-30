// VM Tracker Android client.
// Talks to the same REST API as the web console using the X-VMT-Token header.
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

void main() => runApp(const VmApp());

// ---------------------------------------------------------------- theme
const bg = Color(0xFF070B10);
const panel = Color(0xFF0E151D);
const line = Color(0xFF21313F);
const ink = Color(0xFFD8E4EF);
const muted = Color(0xFF67798D);
const accent = Color(0xFF2FD4C8);
const crit = Color(0xFFFF4D63);
const high = Color(0xFFFF8F3F);
const med = Color(0xFFE8C547);
const low = Color(0xFF4FB0E8);

Color sevColour(String s) => switch (s) {
      'Critical' => crit,
      'High' => high,
      'Medium' => med,
      'Low' => low,
      _ => muted,
    };

// ---------------------------------------------------------------- api
class Api {
  static String base = '';
  static String? token;

  static Future<void> loadBase() async {
    final p = await SharedPreferences.getInstance();
    base = p.getString('base') ?? '';
  }

  static Future<void> saveBase(String v) async {
    base = v.trim().replaceAll(RegExp(r'/$'), '');
    (await SharedPreferences.getInstance()).setString('base', base);
  }

  static Map<String, String> get _headers => {
        'Content-Type': 'application/json',
        if (token != null) 'X-VMT-Token': token!,
      };

  static Future<dynamic> get(String path) async {
    final r = await http.get(Uri.parse('$base$path'), headers: _headers);
    if (r.statusCode == 401) throw 'Session expired — sign in again';
    if (r.statusCode >= 400) throw _detail(r);
    return jsonDecode(r.body);
  }

  static Future<dynamic> post(String path, Map body) async {
    final r = await http.post(Uri.parse('$base$path'),
        headers: _headers, body: jsonEncode(body));
    if (r.statusCode >= 400) throw _detail(r);
    return jsonDecode(r.body);
  }

  static Future<dynamic> patch(String path, Map body) async {
    final r = await http.patch(Uri.parse('$base$path'),
        headers: _headers, body: jsonEncode(body));
    if (r.statusCode >= 400) throw _detail(r);
    return jsonDecode(r.body);
  }

  static String _detail(http.Response r) {
    try {
      return jsonDecode(r.body)['detail']?.toString() ?? 'HTTP ${r.statusCode}';
    } catch (_) {
      return 'HTTP ${r.statusCode}';
    }
  }

  static Future<Map> login(String user, String pass) async {
    final res = await post('/api/auth/login',
        {'username': user, 'password': pass, 'client': 'android'});
    token = res['token'];
    return res['user'];
  }
}

// ---------------------------------------------------------------- app
class VmApp extends StatelessWidget {
  const VmApp({super.key});

  @override
  Widget build(BuildContext context) {
    final theme = ThemeData.dark(useMaterial3: true).copyWith(
      scaffoldBackgroundColor: bg,
      colorScheme: ColorScheme.fromSeed(
          seedColor: accent, brightness: Brightness.dark, surface: panel),
      cardTheme: const CardThemeData(color: panel),
      appBarTheme: const AppBarTheme(backgroundColor: panel, foregroundColor: ink),
      inputDecorationTheme: const InputDecorationTheme(
        filled: true,
        fillColor: Color(0xFF0A1016),
        border: OutlineInputBorder(borderSide: BorderSide(color: line)),
      ),
    );
    return MaterialApp(
      title: 'VM Tracker',
      theme: theme,
      debugShowCheckedModeBanner: false,
      home: const LoginPage(),
    );
  }
}

// ---------------------------------------------------------------- login
class LoginPage extends StatefulWidget {
  const LoginPage({super.key});
  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final server = TextEditingController();
  final user = TextEditingController();
  final pass = TextEditingController();
  String? error;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    Api.loadBase().then((_) => setState(() => server.text = Api.base));
  }

  Future<void> signIn() async {
    setState(() { busy = true; error = null; });
    try {
      await Api.saveBase(server.text);
      final u = await Api.login(user.text.trim(), pass.text);
      if (!mounted) return;
      Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (_) => HomePage(user: u)));
    } catch (e) {
      setState(() => error = e.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        body: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(26),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              const Text('VM TRACKER',
                  style: TextStyle(
                      fontFamily: 'monospace', fontSize: 22,
                      letterSpacing: 4, color: accent, fontWeight: FontWeight.bold)),
              const SizedBox(height: 6),
              const Text('Vulnerability register and closure tracking',
                  style: TextStyle(color: muted, fontSize: 12)),
              const SizedBox(height: 28),
              TextField(
                  controller: server,
                  decoration: const InputDecoration(
                      labelText: 'Server address',
                      hintText: 'http://10.0.20.5:9797')),
              const SizedBox(height: 12),
              TextField(controller: user,
                  decoration: const InputDecoration(labelText: 'Username')),
              const SizedBox(height: 12),
              TextField(controller: pass, obscureText: true,
                  onSubmitted: (_) => signIn(),
                  decoration: const InputDecoration(labelText: 'Password')),
              if (error != null)
                Padding(padding: const EdgeInsets.only(top: 14),
                    child: Text(error!, style: const TextStyle(color: crit, fontSize: 12))),
              const SizedBox(height: 20),
              SizedBox(
                width: double.infinity,
                child: FilledButton(
                    onPressed: busy ? null : signIn,
                    child: Text(busy ? 'Signing in…' : 'Sign in')),
              ),
            ]),
          ),
        ),
      );
}

// ---------------------------------------------------------------- home
class HomePage extends StatefulWidget {
  final Map user;
  const HomePage({super.key, required this.user});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  int tab = 0;

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(
          title: Text(tab == 0 ? 'Executive view' : 'Register',
              style: const TextStyle(fontSize: 16, letterSpacing: 1.5)),
          actions: [
            Padding(
              padding: const EdgeInsets.only(right: 14),
              child: Center(
                child: Text('${widget.user['username']} · ${widget.user['role']}',
                    style: const TextStyle(color: muted, fontSize: 11)),
              ),
            ),
          ],
        ),
        body: tab == 0 ? const DashboardTab() : const RegisterTab(),
        bottomNavigationBar: NavigationBar(
          backgroundColor: panel,
          selectedIndex: tab,
          onDestinationSelected: (i) => setState(() => tab = i),
          destinations: const [
            NavigationDestination(icon: Icon(Icons.dashboard_outlined), label: 'Dashboard'),
            NavigationDestination(icon: Icon(Icons.list_alt_outlined), label: 'Register'),
          ],
        ),
      );
}

// ---------------------------------------------------------------- dashboard
class DashboardTab extends StatefulWidget {
  const DashboardTab({super.key});
  @override
  State<DashboardTab> createState() => _DashboardTabState();
}

class _DashboardTabState extends State<DashboardTab> {
  Map? data;
  String? error;

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    try {
      final d = await Api.get('/api/dashboard/executive');
      setState(() { data = d; error = null; });
    } catch (e) {
      setState(() => error = e.toString());
    }
  }

  Widget tile(String label, String value, {Color? colour}) => Card(
        shape: RoundedRectangleBorder(
            side: const BorderSide(color: line), borderRadius: BorderRadius.circular(3)),
        child: Padding(
          padding: const EdgeInsets.all(13),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(value,
                style: TextStyle(
                    fontFamily: 'monospace', fontSize: 25,
                    fontWeight: FontWeight.bold, color: colour ?? ink)),
            const SizedBox(height: 3),
            Text(label.toUpperCase(),
                style: const TextStyle(color: muted, fontSize: 9.5, letterSpacing: 1.2)),
          ]),
        ),
      );

  @override
  Widget build(BuildContext context) {
    if (error != null) {
      return Center(
          child: Padding(padding: const EdgeInsets.all(24),
              child: Text(error!, style: const TextStyle(color: crit))));
    }
    if (data == null) return const Center(child: CircularProgressIndicator(color: accent));

    final k = data!['kpis'] as Map;
    final sev = (data!['severity'] as List).cast<Map>();
    final depts = (data!['by_department'] as List).cast<Map>();

    return RefreshIndicator(
      onRefresh: load,
      color: accent,
      backgroundColor: panel,
      child: ListView(padding: const EdgeInsets.all(12), children: [
        GridView.count(
          crossAxisCount: 2, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(),
          childAspectRatio: 1.75, mainAxisSpacing: 2, crossAxisSpacing: 2,
          children: [
            tile('Open findings', '${k['open']}'),
            tile('Critical open', '${k['open_critical']}', colour: crit),
            tile('High open', '${k['open_high']}', colour: high),
            tile('Past SLA', '${k['open_breached']}', colour: crit),
            tile('SLA breach rate', '${k['sla_breach_rate']}%'),
            tile('MTTR', '${k['mttr_days']}d'),
          ],
        ),
        const SizedBox(height: 10),
        _section('Severity of open findings'),
        ...sev.where((s) => (s['n'] as int) > 0).map((s) => ListTile(
              dense: true,
              leading: Container(width: 10, height: 10,
                  decoration: BoxDecoration(color: sevColour(s['severity']),
                      borderRadius: BorderRadius.circular(2))),
              title: Text('${s['severity']}', style: const TextStyle(fontSize: 13)),
              trailing: Text('${s['n']}   ${s['breached']} late',
                  style: const TextStyle(fontFamily: 'monospace', color: muted, fontSize: 12)),
            )),
        const SizedBox(height: 10),
        _section('By department'),
        ...depts.map((d) => ListTile(
              dense: true,
              title: Text('${d['grp']}', style: const TextStyle(fontSize: 13)),
              subtitle: Text('crit ${d['critical']} · high ${d['high']} · ${d['breached']} past SLA',
                  style: const TextStyle(color: muted, fontSize: 11)),
              trailing: Text('${d['open']}',
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 15)),
            )),
      ]),
    );
  }

  Widget _section(String t) => Padding(
        padding: const EdgeInsets.fromLTRB(4, 12, 4, 4),
        child: Text(t.toUpperCase(),
            style: const TextStyle(color: muted, fontSize: 10, letterSpacing: 1.6)),
      );
}

// ---------------------------------------------------------------- register
class RegisterTab extends StatefulWidget {
  const RegisterTab({super.key});
  @override
  State<RegisterTab> createState() => _RegisterTabState();
}

class _RegisterTabState extends State<RegisterTab> {
  List rows = [];
  int total = 0;
  String severity = 'any';
  String query = '';
  bool loading = true;
  String? error;

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    setState(() => loading = true);
    final params = <String>['status=open', 'page_size=100', 'sort=severity'];
    if (severity != 'any') params.add('severity=$severity');
    if (query.isNotEmpty) params.add('q=${Uri.encodeQueryComponent(query)}');
    try {
      final d = await Api.get('/api/findings?${params.join('&')}');
      setState(() {
        rows = d['rows'];
        total = d['total'];
        error = null;
      });
    } catch (e) {
      setState(() => error = e.toString());
    } finally {
      setState(() => loading = false);
    }
  }

  Future<void> setStatus(Map row, String status) async {
    try {
      await Api.patch('/api/findings/${row['id']}', {'status': status});
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Finding ${row['id']} set to $status')));
      load();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Could not update: $e')));
    }
  }

  void openSheet(Map r) => showModalBottomSheet(
        context: context,
        backgroundColor: panel,
        isScrollControlled: true,
        builder: (_) => Padding(
          padding: const EdgeInsets.all(18),
          child: Column(mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('${r['title']}',
                style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold)),
            const SizedBox(height: 10),
            _kv('Host', '${r['hostname']}'),
            _kv('Type', '${r['category']} / ${r['subcategory'] ?? '—'}'),
            _kv('Severity', '${r['severity']}  CVSS ${r['cvss_score'] ?? '—'}'),
            _kv('Department', '${r['department'] ?? '—'}'),
            _kv('Application', '${r['application'] ?? '—'}'),
            _kv('System owner', '${r['system_owner'] ?? '—'}'),
            _kv('Age', '${r['age_days']} days (due ${r['due_date'] ?? '—'})'),
            _kv('Status', '${r['status']}'),
            const SizedBox(height: 16),
            Wrap(spacing: 8, children: [
              for (final s in ['mitigated', 'closed', 'risk_accepted', 'false_positive'])
                OutlinedButton(
                    onPressed: () { Navigator.pop(context); setStatus(r, s); },
                    child: Text(s.replaceAll('_', ' '),
                        style: const TextStyle(fontSize: 12))),
            ]),
            const SizedBox(height: 10),
          ]),
        ),
      );

  Widget _kv(String k, String v) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          SizedBox(width: 108,
              child: Text(k.toUpperCase(),
                  style: const TextStyle(color: muted, fontSize: 9.5, letterSpacing: 1.1))),
          Expanded(child: Text(v, style: const TextStyle(fontSize: 12.5))),
        ]),
      );

  @override
  Widget build(BuildContext context) => Column(children: [
        Padding(
          padding: const EdgeInsets.all(10),
          child: Row(children: [
            Expanded(
              child: TextField(
                onSubmitted: (v) { query = v; load(); },
                decoration: const InputDecoration(
                    isDense: true, hintText: 'Search host, vulnerability, CVE'),
              ),
            ),
            const SizedBox(width: 8),
            DropdownButton<String>(
              value: severity,
              dropdownColor: panel,
              underline: const SizedBox.shrink(),
              items: ['any', 'Critical', 'High', 'Medium', 'Low']
                  .map((s) => DropdownMenuItem(value: s,
                      child: Text(s, style: const TextStyle(fontSize: 13))))
                  .toList(),
              onChanged: (v) { severity = v!; load(); },
            ),
          ]),
        ),
        if (error != null)
          Padding(padding: const EdgeInsets.all(16),
              child: Text(error!, style: const TextStyle(color: crit))),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14),
          child: Row(children: [
            Text('$total open findings',
                style: const TextStyle(color: muted, fontSize: 11)),
          ]),
        ),
        Expanded(
          child: loading
              ? const Center(child: CircularProgressIndicator(color: accent))
              : RefreshIndicator(
                  onRefresh: load, color: accent, backgroundColor: panel,
                  child: ListView.separated(
                    itemCount: rows.length,
                    separatorBuilder: (_, __) => const Divider(height: 1, color: line),
                    itemBuilder: (_, i) {
                      final r = rows[i] as Map;
                      final late = r['sla_breached'] == 1;
                      return ListTile(
                        onTap: () => openSheet(r),
                        leading: Container(width: 4, height: 40,
                            color: sevColour('${r['severity']}')),
                        title: Text('${r['title']}',
                            maxLines: 2, overflow: TextOverflow.ellipsis,
                            style: const TextStyle(fontSize: 13)),
                        subtitle: Text(
                            '${r['hostname']} · ${r['category']} · ${r['department'] ?? 'no department'}',
                            style: const TextStyle(color: muted, fontSize: 11)),
                        trailing: Text('${r['age_days']}d',
                            style: TextStyle(
                                fontFamily: 'monospace',
                                color: late ? crit : muted, fontSize: 12)),
                      );
                    },
                  ),
                ),
        ),
      ]);
}
