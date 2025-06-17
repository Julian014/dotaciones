import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:aplicacion_conductores/screens/pagos.dart';
import 'domicilios.dart';
// import 'package:lottie/lottie.dart'; // Comentado porque no se usarán animaciones por ahora
import 'package:aplicacion_conductores/screens/login_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:aplicacion_conductores/screens/blog_screen.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:url_launcher/url_launcher_string.dart';

class AnimatedBadge extends StatefulWidget {
  final int count;
  const AnimatedBadge({Key? key, required this.count}) : super(key: key);

  @override
  _AnimatedBadgeState createState() => _AnimatedBadgeState();
}

class _AnimatedBadgeState extends State<AnimatedBadge>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _animation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: Duration(milliseconds: 800),
    )..repeat(reverse: true);
    _animation = Tween<double>(begin: 1.0, end: 1.5).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOutBack),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }






  @override
  Widget build(BuildContext context) {
    return ScaleTransition(
      scale: _animation,
      child: Container(
        padding: EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: Colors.redAccent,
          shape: BoxShape.circle,
        ),
        child: Text(
          '${widget.count}',
          style: TextStyle(
            color: Colors.white,
            fontSize: 16,
            fontWeight: FontWeight.bold,
          ),
          textAlign: TextAlign.center,
        ),
      ),
    );
  }
}

class HomeScreen extends StatefulWidget {
  final String userId;
  HomeScreen({required this.userId});

  @override
  _HomeScreenState createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  Timer? _timer;
  final List<Map<String, dynamic>> rooms = [
    {"name": "Pagos", "devices": 10, "image": "assets/images/pagos.png", "pendientes": 2},
    {"name": "Domicilios", "devices": 5, "image": "assets/images/domicilios.png", "pendientes": 0},
    {"name": "Informes", "devices": 3, "image": "assets/images/informe.png", "pendientes": 1},
  ];
  final String logoImage = 'assets/images/2022cercetafinal_blanco.png';

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(Duration(seconds: 3), (timer) {
      setState(() {});
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

Future<int> fetchApartamento(String userId) async {
  try {
    final url = 'https://sistemacerceta.com/user_info/$userId';

    final response = await http.get(Uri.parse(url));

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      return int.parse(data['apartamento']); // ✅ conversión aquí
    } else {
      throw Exception("Error al cargar el apartamento");
    }
  } catch (e) {
    print('Error en fetchApartamento: $e');
    rethrow;
  }
}

  Future<int> fetchDomiciliosPendientes(String userId) async {
    final url = 'https://sistemacerceta.com/domicilios_pendientes/$userId';
    final response = await http.get(Uri.parse(url));
    if (response.statusCode == 200) {
      final List<dynamic> data = jsonDecode(response.body);
      int count = data.where((d) => d["estado"] == 1).length;
      return count;
    } else {
      throw Exception("Error al cargar domicilios");
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            colors: [Color(0xFFE3F2FD), Color(0xFFFFFFFF)],
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
          ),
        ),
        child: SafeArea(
          child: Column(
            children: [
              _buildAppBar(context),
              Expanded(child: _buildContent(context)),
            ],
          ),
        ),
      ),
      bottomNavigationBar: _buildBottomNavigationBar(context),
    );
  }

  Widget _buildAppBar(BuildContext context) {
    return Stack(
      children: [




 Container(
  height: 100,
  decoration: BoxDecoration(
    gradient: LinearGradient(
      colors: [
        Color(0xFFB3E5FC), // azul cielo claro
        Color(0xFFE1F5FE), // casi blanco azulado
      ],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    ),
    borderRadius: BorderRadius.only(
      bottomLeft: Radius.circular(30),
      bottomRight: Radius.circular(30),
    ),
  ),
),




        Positioned(
          top: 20,
          left: 20,
          right: 20,
          child: Row(
            children: [
              ClipOval(
                child: Image.asset(
                  logoImage,
                  height: 50,
                  width: 50,
                  fit: BoxFit.cover,
                ),
              ),
              SizedBox(width: 12),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text("¡Bienvenido!", style: TextStyle(color: Colors.white70, fontSize: 14)),
                  Text("Menú Principal", style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.bold)),
                ],
              ),
              Spacer(),
              Icon(Icons.notifications, color: Colors.white, size: 30)
            ],
          ),
        )
      ],
    );
  }

  Widget _buildContent(BuildContext context) {
    return SingleChildScrollView(
      child: Padding(
        padding: EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildApartmentCard(),
            SizedBox(height: 20),
            Text("Secciones", style: TextStyle(fontSize: 24, fontWeight: FontWeight.w700)),
            SizedBox(height: 12),
            _buildRoomsGrid(context),
            SizedBox(height: 20),
          ],
        ),
      ),
    );
  }

  Widget _buildApartmentCard() {
    return FutureBuilder<int>(
      future: fetchApartamento(widget.userId),
      builder: (context, snapshot) {
        String aptText = "Cargando...";
        if (snapshot.hasData) {
          aptText = "Apartamento: ${snapshot.data}";
        } else if (snapshot.hasError) {
          aptText = "Error al cargar";
        }
        return Container(
          padding: EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: Colors.blue[700],
            borderRadius: BorderRadius.circular(20),
            boxShadow: [
              BoxShadow(
                color: Colors.black12,
                blurRadius: 8,
                offset: Offset(0, 4),
              ),
            ],
          ),
          child: Row(
            children: [
              Icon(Icons.apartment, color: Colors.white, size: 32),
              SizedBox(width: 16),
              Text(
                aptText,
                style: TextStyle(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold),
              )
            ],
          ),
        );
      },
    );
  }

  Widget _buildRoomsGrid(BuildContext context) {
    return GridView.builder(
      itemCount: rooms.length,
      shrinkWrap: true,
      physics: NeverScrollableScrollPhysics(),
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        crossAxisSpacing: 16,
        mainAxisSpacing: 16,
        childAspectRatio: 0.9,
      ),
      itemBuilder: (context, index) {
        final room = rooms[index];

        return GestureDetector(
          onTap: () {
            if (room["name"] == "Domicilios") {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => PedidosScreen(userId: widget.userId),
                ),
              );
            } else if (room["name"] == "Pagos") {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => NuevoPagoScreen(userId: widget.userId),
                ),
              );
            }
          },
          child: AnimatedContainer(
            duration: Duration(milliseconds: 400),
            curve: Curves.easeInOut,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(20),
              gradient: LinearGradient(
                colors: [Colors.white, Colors.grey.shade50],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              boxShadow: [
                BoxShadow(
                  color: Colors.grey.shade300,
                  blurRadius: 12,
                  offset: Offset(0, 6),
                ),
              ],
            ),
            child: Stack(
              children: [
                Center(
                  child: Padding(
                    padding: EdgeInsets.symmetric(horizontal: 12, vertical: 18),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Image.asset(room["image"], height: 64),
                        SizedBox(height: 12),
                        Text(
                          room["name"],
                          style: TextStyle(
                            fontSize: 17,
                            fontWeight: FontWeight.w600,
                            color: Colors.black87,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
                if (room["name"] == "Domicilios")
                  FutureBuilder<int>(
                    future: fetchDomiciliosPendientes(widget.userId),
                    builder: (context, snapshot) {
                      if (snapshot.connectionState == ConnectionState.waiting) {
                        return Positioned(
                          right: 12,
                          top: 12,
                          child: Container(
                            width: 24,
                            height: 24,
                            alignment: Alignment.center,
                            decoration: BoxDecoration(
                              color: Colors.redAccent,
                              shape: BoxShape.circle,
                            ),
                            child: CircularProgressIndicator(
                              valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                              strokeWidth: 2,
                            ),
                          ),
                        );
                      }
                      if (snapshot.hasError) {
                        return Positioned(
                          right: 12,
                          top: 12,
                          child: Icon(Icons.error, color: Colors.redAccent, size: 22),
                        );
                      }
                      if (snapshot.hasData && snapshot.data! > 0) {
                        return Positioned(
                          right: 12,
                          top: 12,
                          child: AnimatedBadge(count: snapshot.data!),
                        );
                      }
                      return Container();
                    },
                  )
                else if (room["pendientes"] > 0)
                  Positioned(
                    right: 12,
                    top: 12,
                    child: Container(
                      padding: EdgeInsets.all(6),
                      decoration: BoxDecoration(
                        color: Colors.redAccent,
                        shape: BoxShape.circle,
                      ),
                      child: Text(
                        '${room["pendientes"]}',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 13,
                          fontWeight: FontWeight.bold,
                        ),
                        textAlign: TextAlign.center,
                      ),
                    ),
                  ),
              ],
            ),
          ),
        );
      },
    );
  }

Widget _buildBottomNavigationBar(BuildContext context) {
  return Container(
    decoration: BoxDecoration(
      color: Colors.white,
      boxShadow: [
        BoxShadow(
          color: Colors.grey.shade400,
          blurRadius: 10,
          offset: Offset(0, -2),
        ),
      ],
      borderRadius: BorderRadius.only(
        topLeft: Radius.circular(20),
        topRight: Radius.circular(20),
      ),
    ),
    child: BottomNavigationBar(
      backgroundColor: Colors.transparent,
      elevation: 0,
      items: [
        BottomNavigationBarItem(icon: Icon(Icons.home), label: 'Home'),
        BottomNavigationBarItem(icon: Icon(Icons.feed), label: 'Blog'),
        BottomNavigationBarItem(icon: Icon(Icons.settings), label: 'Settings'),
        BottomNavigationBarItem(icon: Icon(Icons.logout), label: 'Cerrar sesión'),
      ],
      currentIndex: 0,
      selectedItemColor: Colors.deepPurple,
      unselectedItemColor: Colors.grey,
      type: BottomNavigationBarType.fixed,



onTap: (index) async {
  if (index == 0) {
    // Ya estás en Home
  } else if (index == 1) {
    final url = 'https://sistemacerceta.com/blog_residentes_app/${widget.userId}';

    if (await canLaunchUrlString(url)) {
      await launchUrlString(url, mode: LaunchMode.externalApplication);
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('No se pudo abrir el blog')),
      );
    }
  } else if (index == 2) {
    // Aquí podrías abrir Settings si existe
  } else if (index == 3) {
    final prefs = await SharedPreferences.getInstance();

    await prefs.remove('user_token');
    await prefs.remove('user_id');

    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (context) => LoginScreen()),
      (Route<dynamic> route) => false,
    );
  }
},


    ),
  );
}

} // cierra _HomeScreenState


