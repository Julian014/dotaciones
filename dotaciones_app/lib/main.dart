import 'package:flutter/material.dart';
import 'package:firebase_core/firebase_core.dart';
import 'firebase_options.dart';
import 'package:firebase_auth/firebase_auth.dart';
import 'package:firebase_messaging/firebase_messaging.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'screens/login_screen.dart';
import 'screens/home_screen.dart';
import 'screens/autorizaciones.dart';

Future<void> _firebaseMessagingBackgroundHandler(RemoteMessage message) async {
  print("🔵 Notificación en segundo plano: ${message.notification?.title}, ${message.notification?.body}");
}

Future<Map<String, String?>> getSession() async {
  final prefs = await SharedPreferences.getInstance();
  return {
    'token': prefs.getString('user_token'),
    'userId': prefs.getString('user_id'),
  };
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await Firebase.initializeApp(options: DefaultFirebaseOptions.currentPlatform);
  FirebaseMessaging.onBackgroundMessage(_firebaseMessagingBackgroundHandler);
  runApp(MyApp());
}

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  bool _isLoading = true;
  String? _userId;
  bool _isLoggedIn = false;
  ThemeMode _themeMode = ThemeMode.light;

  @override
  void initState() {
    super.initState();
    _loadSession();

    FirebaseMessaging.onMessage.listen((RemoteMessage message) {
      print("🔔 Notificación recibida en primer plano: ${message.notification?.title}, ${message.notification?.body}");
    });

    FirebaseMessaging.onMessageOpenedApp.listen((RemoteMessage message) {
      print("📩 Notificación abierta: ${message.notification?.title}, ${message.notification?.body}");
    });
  }

  Future<void> _loadSession() async {
    final prefs = await SharedPreferences.getInstance();
    var sessionData = await getSession();
    final isDark = prefs.getBool('is_dark_theme') ?? false;

    setState(() {
      _userId = sessionData['userId'];
      _isLoggedIn = sessionData['token'] != null;
      _themeMode = isDark ? ThemeMode.dark : ThemeMode.light;
      _isLoading = false;
    });
  }

  Future<void> _toggleTheme() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _themeMode = _themeMode == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark;
    });
    await prefs.setBool('is_dark_theme', _themeMode == ThemeMode.dark);
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Aplicación Conductores',
      debugShowCheckedModeBanner: false,

      theme: ThemeData(
        brightness: Brightness.light,
        scaffoldBackgroundColor: const Color(0xFFF5F6FA),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF1E99D3),
          foregroundColor: Colors.white,
        ),
        colorScheme: const ColorScheme.light(
          primary: Color(0xFF1E99D3),
          secondary: Color(0xFF673AB7),
          background: Color(0xFFF5F6FA),
          surface: Colors.white,
          onPrimary: Colors.white,
          onSurface: Colors.black87,
        ),
      ),

      darkTheme: ThemeData(
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF2B2B2B),
        cardColor: const Color(0xFF3A3A3A),
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF2B2B2B),
          foregroundColor: Colors.white,
        ),
        colorScheme: const ColorScheme(
          brightness: Brightness.dark,
          primary: Color(0xFFBB86FC),
          secondary: Color(0xFF03DAC6),
          background: Color(0xFF2B2B2B),
          surface: Color(0xFF3A3A3A),
          onPrimary: Colors.white,
          onSecondary: Colors.black,
          onBackground: Colors.white70,
          onSurface: Colors.white,
          error: Colors.red,
          onError: Colors.white,
        ),
      ),

      themeMode: _themeMode,

      home: _isLoading
          ? const Scaffold(body: Center(child: CircularProgressIndicator()))
          : _isLoggedIn && _userId != null
              ? HomeScreen(userId: _userId!, onToggleTheme: _toggleTheme)
              : LoginScreen(),

      routes: {
        '/home': (context) => HomeScreen(userId: _userId ?? '', onToggleTheme: _toggleTheme),
      },
    );
  }
}
