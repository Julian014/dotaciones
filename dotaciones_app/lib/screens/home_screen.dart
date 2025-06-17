import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher_string.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'pagos.dart';
import 'domicilios.dart';
import 'login_screen.dart';
import 'informes_screen.dart';
import 'pqrs_screen.dart';
import 'vista_general_page.dart';
import 'autorizaciones.dart';

class HomeScreen extends StatefulWidget {
  final String userId;
  final VoidCallback? onToggleTheme;

  const HomeScreen({
    super.key,
    required this.userId,
    this.onToggleTheme,
  });

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  Timer? _timer;
  int pendingDomicilios = 0;
  int? apartment;
  String? userName;
  String? responsible;
  String? email;
  String? buildingId;
  String? floor;
  String? buildingName;

  final List<Map<String, dynamic>> featureCards = [
    {
      "name": "Domicilios",
      "icon": Icons.local_shipping,
      "color": Colors.blueAccent,
      "screen": PedidosScreen(userId: '') // Se reemplazará
    },
{
  "name": "autorizaciones",
  "icon": Icons.assignment_turned_in,  // Icono de documento con check
  "color": Colors.greenAccent,
    "screen": (String userId) => AutorizacionesScreen(userId: userId),
},
    {
      "name": "PQRS",
      "icon": Icons.contact_support,
      "color": Colors.orangeAccent,
      "screen": PqrsScreen(userId: '')
    },
    {
      "name": "Pagos",
      "icon": Icons.payment,
      "color": Colors.purpleAccent,
      "screen": NuevoPagoScreen(userId: '')
    },
  ];

  @override
  void initState() {
    super.initState();
    fetchUserInfo();
    fetchDomiciliosPendientes();
    _timer = Timer.periodic(const Duration(seconds: 10), (_) => fetchDomiciliosPendientes());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _logout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('userId');
    Navigator.pushAndRemoveUntil(
      context,
      MaterialPageRoute(builder: (context) => LoginScreen()),
      (Route<dynamic> route) => false,
    );
  }

  Future<void> fetchDomiciliosPendientes() async {
    try {
      final response = await http.get(Uri.parse('https://sistemacerceta.com/domicilios_pendientes/${widget.userId}'));
      if (response.statusCode == 200) {
        final List<dynamic> data = jsonDecode(response.body);
        final count = data.where((d) => d["estado"] == 1).length;
        setState(() => pendingDomicilios = count);
      }
    } catch (_) {}
  }

  Future<void> fetchUserInfo() async {
    try {
      final response = await http.get(Uri.parse('https://sistemacerceta.com/user_info/${widget.userId}'));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        setState(() {
          apartment = int.tryParse(data['apartamento'].toString());
          userName = data['nombre'] ?? 'Usuario';
          buildingId = data['edificio_id']?.toString() ?? '';
          buildingName = data['edificio_nombre'] ?? 'Sin nombre';
          responsible = data['responsable'] ?? '';
          floor = data['piso']?.toString() ?? '';
          email = data['correo'] ?? '';
        });
      } else {
        setState(() => userName = 'Usuario');
      }
    } catch (_) {
      setState(() => userName = 'Usuario');
    }
  }



@override
Widget build(BuildContext context) {
  final isDarkMode = Theme.of(context).brightness == Brightness.dark;
  final primaryColor = isDarkMode ? Colors.blueAccent[400]! : const Color(0xFF1E99D3);
  final bgColor = isDarkMode ? const Color(0xFF121212) : const Color(0xFFF5F6FA);

  return Stack(
    children: [
      Scaffold(
        backgroundColor: bgColor,
        extendBody: true,
        body: CustomScrollView(
          slivers: [
            // AppBar personalizado
            // AppBar personalizado
SliverAppBar(
  expandedHeight: 220.0,
  floating: false,
  pinned: true,
  flexibleSpace: FlexibleSpaceBar(
    background: _buildHeader(primaryColor, isDarkMode),
    title: Text(
      'Hola, ${userName?.split(" ").first ?? ''}',
      style: TextStyle(
        color: Colors.white,
        fontSize: 18,
        shadows: [
          Shadow(
            blurRadius: 10.0,
            color: Colors.black.withOpacity(0.5),
            offset: const Offset(1.0, 1.0),
          ),
        ],
      ),
    ),
    centerTitle: true,
  ),
  actions: [
    // Nuevo ícono para información de usuario
    IconButton(
      icon: const Icon(Icons.account_circle),
      onPressed: () {
        setState(() {
          _showUserInfo = !_showUserInfo;
        });
      },
      color: Colors.white,
    ),
    // Ícono original de notificaciones
    IconButton(
      icon: const Icon(Icons.notifications_none),
      onPressed: () {},
      color: Colors.white,
    ),
  ],
),
// Contenido principal
SliverToBoxAdapter(
  child: Padding(
    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
    child: Column(
      children: [
        if (_showUserInfo)
          _buildUserInfoCard(isDarkMode).animate().fadeIn().slideY(begin: 0.1, end: 0),

        _buildPaymentCard(isDarkMode, primaryColor),
        const SizedBox(height: 25),

        // 👉 SECCIÓN DEL BLOG después de Gestión de Pagos
        _buildBlogSection(),
        const SizedBox(height: 25),

        _buildFeaturesSection(isDarkMode),
        const SizedBox(height: 25),

        const SizedBox(height: 80),
      ],
    ),
  ),
),


          ],
        ),
        bottomNavigationBar: _buildBottomNav(context, isDarkMode),
      ),


      
      // Aquí añadimos el ícono flotante sin modificar nada más
      Positioned(
        bottom: 100,
        right: 20,
        child: GestureDetector(
          onTap: () async {
            final url = 'https://sistemacerceta.com/blog_residentes_app/${widget.userId}';
            if (await canLaunchUrlString(url)) {
              await launchUrlString(url, mode: LaunchMode.externalApplication);
            }
          },
          child: Container(
            width: 60,
            height: 60,
            decoration: BoxDecoration(
              color: const Color(0xFF1E99D3),
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.3),
                  blurRadius: 15,
                  spreadRadius: 2,
                  offset: const Offset(0, 5),
                ),
              ],
            ),
            child: const Icon(
              Icons.article_outlined,
              color: Colors.white,
              size: 28,
            ),
          ),
        ),
      ),
    ],
  );
}






// En tu clase de estado, declara la variable
bool _showUserInfo = false;

// Método para construir la sección completa
Widget _buildUserInfoSection(bool isDarkMode) {
  return Column(
    children: [
      // Botón del ícono de usuario
      GestureDetector(
        onTap: () {
          setState(() {
            _showUserInfo = !_showUserInfo;
          });
        },
        child: Container(
          padding: EdgeInsets.all(8),
          child: Icon(
            Icons.account_circle,
            size: 36,
            color: isDarkMode ? Colors.white : Colors.black87,
          ),
        ),
      ),
      
      // Espacio entre el ícono y la tarjeta
      SizedBox(height: 8),
      
      // Tarjeta de información (solo visible cuando _showUserInfo es true)
      if (_showUserInfo) 
        _buildUserInfoCard(isDarkMode).animate().fadeIn().slideY(begin: 0.1, end: 0),
    ],
  );
}

// Método para construir la tarjeta de información (igual al que tenías)
Widget _buildUserInfoCard(bool isDarkMode) {
  return Card(
    elevation: 0,
    shape: RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(20),
    ),
    color: isDarkMode ? const Color(0xFF1E1E1E) : Colors.white,
    child: Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.person_outline, size: 24),
              const SizedBox(width: 10),
              Text(
                'Tu Información',
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.bold,
                  color: isDarkMode ? Colors.white : Colors.black87,
                ),
              ),
            ],
          ),
          const SizedBox(height: 15),
          _buildInfoItem('ID Usuario', widget.userId.toString(), Icons.fingerprint),
          _buildInfoItem('Apartamento', apartment?.toString() ?? 'Cargando...', Icons.home),
          _buildInfoItem('Edificio', buildingName ?? 'Cargando...', Icons.apartment),
          _buildInfoItem('Piso', floor ?? 'Cargando...', Icons.stairs),
          _buildInfoItem('Responsable', responsible ?? 'Cargando...', Icons.supervisor_account),
          _buildInfoItem('Correo', email ?? 'Cargando...', Icons.email),
        ],
      ),
    ),
  );
}









// Añade este widget en tu Stack principal del home (fuera de cualquier Column)
Widget _buildFloatingBlogAccess() {
  return Positioned(
    bottom: 100,  // Ajusta según necesidad
    right: 20,
    child: GestureDetector(
      onTap: () async {
        final url = 'https://sistemacerceta.com/blog_residentes_app/${widget.userId}';
        if (await canLaunchUrlString(url)) {
          await launchUrlString(url, mode: LaunchMode.externalApplication);
        }
      },
      child: MouseRegion(
        cursor: SystemMouseCursors.click,
        child: Container(
          width: 60,
          height: 60,
          decoration: BoxDecoration(
            color: const Color(0xFF1E99D3),
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.3),
                blurRadius: 15,
                spreadRadius: 2,
                offset: const Offset(0, 5),
              ),
            ],
          ),
          child: Stack(
            children: [
              // Efecto de burbuja
              Positioned.fill(
                child: Container(
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: RadialGradient(
                      colors: [
                        Colors.white.withOpacity(0.3),
                        Colors.transparent,
                      ],
                      stops: const [0.1, 0.8],
                    ),
                  ),
                ),
              ),
              
              // Notificación de nuevo contenido
              Positioned(
                top: 5,
                right: 5,
                child: Container(
                  width: 12,
                  height: 12,
                  decoration: const BoxDecoration(
                    color: Colors.redAccent,
                    shape: BoxShape.circle,
                  ),
                ),
              ),
              
              // Icono principal
              const Center(
                child: Icon(
                  Icons.article_outlined,
                  color: Colors.white,
                  size: 28,
                ),
              ),
              
              // Efecto de onda al hacer tap
              Positioned.fill(
                child: Material(
                  color: Colors.transparent,
                  child: InkWell(
                    borderRadius: BorderRadius.circular(30),
                    onTap: null, // El GestureDetector padre ya maneja el tap
                    splashColor: Colors.white.withOpacity(0.3),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    ),
  );
}











  Widget _buildHeader(Color primaryColor, bool isDarkMode) {
    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [
            primaryColor,
            isDarkMode ? Colors.blue[900]! : Colors.blue[400]!,
          ],
        ),
        borderRadius: const BorderRadius.only(
          bottomLeft: Radius.circular(30),
          bottomRight: Radius.circular(30),
        ),
      ),
      child: Stack(
        children: [
          Positioned(
            right: -50,
            top: -50,
            child: Container(
              width: 200,
              height: 200,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: Colors.white.withOpacity(0.1),
              ),
            ),
          ),
          Positioned(
            left: -30,
            bottom: -30,
            child: Container(
              width: 150,
              height: 150,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: Colors.white.withOpacity(0.1),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(top: 80, left: 20, right: 20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Barra de búsqueda
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  decoration: BoxDecoration(
                    color: isDarkMode ? Colors.white.withOpacity(0.2) : Colors.white,
                    borderRadius: BorderRadius.circular(24),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withOpacity(0.1),
                        blurRadius: 10,
                        offset: const Offset(0, 5),
                      ),
                    ],
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.search, color: Colors.grey),
                      const SizedBox(width: 10),
                      Expanded(
                        child: TextField(
                          decoration: InputDecoration(
                            border: InputBorder.none,
                            hintText: 'Buscar...',
                            hintStyle: TextStyle(
                              color: isDarkMode ? Colors.white70 : Colors.grey,
                            ),
                          ),
                          style: TextStyle(
                            color: isDarkMode ? Colors.white : Colors.black,
                          ),
                        ),
                      ),
                      GestureDetector(
                        onTap: () => _showSettingsPanel(),
                        child: Container(
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: primaryColor.withOpacity(0.8),
                          ),
                          child: const Icon(Icons.tune, color: Colors.white),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPaymentCard(bool isDarkMode, Color primaryColor) {
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
      ),
      color: isDarkMode ? const Color(0xFF1E1E1E) : Colors.white,
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(20),
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: isDarkMode
                ? [Colors.blue[900]!, Colors.purple[900]!]
                : [primaryColor, Colors.purpleAccent],
          ),
          boxShadow: [
            BoxShadow(
              color: isDarkMode ? Colors.blue.withOpacity(0.3) : Colors.blue.withOpacity(0.5),
              blurRadius: 15,
              offset: const Offset(0, 10),
            ),
          ],
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.payment, color: Colors.white, size: 30),
                const SizedBox(width: 10),
                Text(
                  'Gestión de Pagos',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 20),
            Text(
              'Realiza y gestiona tus pagos de manera rápida y segura',
              style: TextStyle(
                color: Colors.white.withOpacity(0.9),
                fontSize: 14,
              ),
            ),
            const SizedBox(height: 20),
            ElevatedButton(
              onPressed: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (_) => NuevoPagoScreen(userId: widget.userId),
                  ),
                );
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.white,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(30),
                ),
                padding: const EdgeInsets.symmetric(horizontal: 30, vertical: 12),
                elevation: 5,
              ),
              child: Text(
                'Subir Comprobante',
                style: TextStyle(
                  color: primaryColor,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
        ),
      ),
    ).animate().fadeIn(delay: 200.ms).slideY(begin: 0.2, end: 0);
  }












Widget _buildBlogSection() {
  return Padding(
    padding: const EdgeInsets.symmetric(horizontal: 20),
    child: GestureDetector(
      onTap: () async {
        final url = 'https://sistemacerceta.com/blog_residentes_app/${widget.userId}';
        if (await canLaunchUrlString(url)) {
          await launchUrlString(url, mode: LaunchMode.externalApplication);
        }
      },
      child: Container(
        height: 200,
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(30),
          boxShadow: const [
            BoxShadow(
              color: Colors.black26,
              blurRadius: 15,
              offset: Offset(0, 8),
            ),
          ],
          image: const DecorationImage(
            image: AssetImage('assets/images/blog.png'),
            fit: BoxFit.cover,
          ),
        ),
        child: Container(
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(30),
            gradient: LinearGradient(
              colors: [Colors.black.withOpacity(0.6), Colors.transparent],
              begin: Alignment.bottomCenter,
              end: Alignment.topCenter,
            ),
          ),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                const Text(
                  'Explora las últimas noticias',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 22,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                const SizedBox(height: 8),
                Row(
                  children: const [
                    Text(
                      'Ir al Blog',
                      style: TextStyle(
                        color: Colors.white70,
                        fontSize: 16,
                      ),
                    ),
                    SizedBox(width: 8),
                    Icon(Icons.arrow_forward, color: Colors.white70)
                  ],
                )
              ],
            ),
          ),
        ),
      ).animate().fade(duration: 600.ms).slideY(begin: 0.3, curve: Curves.easeOut),
    ),
  );
}







  Widget _buildFeaturesSection(bool isDarkMode) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Servicios',
          style: TextStyle(
            fontSize: 20,
            fontWeight: FontWeight.bold,
            color: isDarkMode ? Colors.white : Colors.black87,
          ),
        ),
        const SizedBox(height: 15),
        GridView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 2,
            childAspectRatio: 1.2,
            crossAxisSpacing: 15,
            mainAxisSpacing: 15,
          ),
          itemCount: featureCards.length,
          itemBuilder: (context, index) {
            final feature = featureCards[index];
            final isDomicilio = feature['name'] == 'Domicilios';
            
            return GestureDetector(
              onTap: () {
                if (feature['screen'] != null) {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (_) => feature['name'] == 'Domicilios'
                          ? PedidosScreen(userId: widget.userId)
                          : feature['name'] == 'Pagos'
                              ? NuevoPagoScreen(userId: widget.userId)
                               : feature['name'] == 'Autorizaciones'
                ? AutorizacionesScreen(userId: widget.userId)
                                  : AutorizacionesScreen(userId: widget.userId),
                    ),
                  );
                }
              },
              child: Container(
                decoration: BoxDecoration(
                  color: isDarkMode ? const Color(0xFF1E1E1E) : Colors.white,
                  borderRadius: BorderRadius.circular(20),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withOpacity(0.1),
                      blurRadius: 10,
                      offset: const Offset(0, 5),
                    ),
                  ],
                ),
                child: Stack(
                  children: [
                    Positioned(
                      top: 15,
                      right: 15,
                      child: Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: feature['color'].withOpacity(0.2),
                          shape: BoxShape.circle,
                        ),
                        child: Icon(feature['icon'], color: feature['color']),
                      ),
                    ),
                    Positioned(
                      bottom: 20,
                      left: 20,
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            feature['name'],
                            style: TextStyle(
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                              color: isDarkMode ? Colors.white : Colors.black87,
                            ),
                          ),
                          const SizedBox(height: 5),
                          Text(
                            'Ver más',
                            style: TextStyle(
                              fontSize: 12,
                              color: isDarkMode ? Colors.white70 : Colors.grey,
                            ),
                          ),
                        ],
                      ),
                    ),
                    if (isDomicilio && pendingDomicilios > 0)
                      Positioned(
                        top: 10,
                        left: 10,
                        child: Container(
                          padding: const EdgeInsets.all(6),
                          decoration: const BoxDecoration(
                            color: Colors.redAccent,
                            shape: BoxShape.circle,
                          ),
                          child: Text(
                            '$pendingDomicilios',
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            );
          },
        ),
      ],
    );
  }




// Versión alternativa más minimalista (opcional)
Widget _buildFloatingBlogAccessV2() {
  return Positioned(
    bottom: 100,
    right: 20,
    child: GestureDetector(
      onTap: () async {
        final url = 'https://sistemacerceta.com/blog_residentes_app/${widget.userId}';
        if (await canLaunchUrlString(url)) {
          await launchUrlString(url, mode: LaunchMode.externalApplication);
        }
      },
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.primary,
          borderRadius: BorderRadius.circular(50),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.2),
              blurRadius: 10,
              offset: const Offset(0, 4),
            ),
          ],
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: const [
            Icon(Icons.newspaper, color: Colors.white),
            SizedBox(width: 8),
            Text(
              'Blog',
              style: TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.bold,
              ),
            ),
          ],
        ),
      ),
    ),
  );
}

// Versión con tooltip (recomendada)
Widget _buildFloatingBlogAccessV3() {
  return Positioned(
    bottom: 100,
    right: 20,
    child: Tooltip(
      message: 'Noticias y actualizaciones',
      child: GestureDetector(
        onTap: () async {
          final url = 'https://sistemacerceta.com/blog_residentes_app/${widget.userId}';
          if (await canLaunchUrlString(url)) {
            await launchUrlString(url, mode: LaunchMode.externalApplication);
          }
        },
        child: Container(
          width: 56,
          height: 56,
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [
                const Color(0xFF1E99D3),
                const Color(0xFF1E99D3).withOpacity(0.8),
              ],
            ),
            shape: BoxShape.circle,
            boxShadow: [
              BoxShadow(
                color: Colors.black.withOpacity(0.2),
                blurRadius: 10,
                spreadRadius: 1,
                offset: const Offset(0, 3),
              ),
            ],
          ),
          child: const Center(
            child: Icon(
              Icons.article,
              color: Colors.white,
              size: 28,
            ),
          ),
        ),
      ),
    ),
  );
}



  Widget _buildInfoItem(String label, String value, IconData icon) {
    final isDarkMode = Theme.of(context).brightness == Brightness.dark;
    
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          Icon(icon, size: 18, color: isDarkMode ? Colors.blueAccent : const Color(0xFF1E99D3)),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                color: isDarkMode ? Colors.white70 : Colors.grey[600],
                fontSize: 14,
              ),
            ),
          ),
          Text(
            value,
            style: TextStyle(
              color: isDarkMode ? Colors.white : Colors.black87,
              fontSize: 14,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

Widget _buildBottomNav(BuildContext context, bool isDarkMode) {
  return Container(
    height: 90,
    decoration: BoxDecoration(
      color: isDarkMode ? const Color(0xFF1E1E1E) : Colors.white,
      borderRadius: const BorderRadius.only(
        topLeft: Radius.circular(30),
        topRight: Radius.circular(30),
      ),
      boxShadow: [
        BoxShadow(
          color: Colors.black.withOpacity(0.1),
          blurRadius: 20,
          offset: const Offset(0, -5),
        ),
      ],
    ),
    child: Row(
      mainAxisAlignment: MainAxisAlignment.spaceAround,
      children: [
        _buildNavItem(Icons.home, 'Inicio', true, () {}),
        _buildNavItem(Icons.public, 'Redes', false, () => _showSocialMediaBottomSheet()),
        IconButton(
          icon: Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.blue,
              shape: BoxShape.circle,
            ),
            child: const Icon(Icons.add, color: Colors.white),
          ),
          onPressed: _handleCentralButtonPress, // Cambiado a método existente
        ),
        _buildNavItem(Icons.settings, 'Ajustes', false, () => _showSettingsPanel()),
        _buildNavItem(Icons.logout, 'Salir', false, _logout),
      ],
    ),
  );
}

// Añade este método en tu clase State
void _handleCentralButtonPress() {
  // Implementa aquí la lógica del botón central
  print('Botón central presionado');
  // Ejemplo:
  // Navigator.push(context, MaterialPageRoute(builder: (_) => NuevaPantalla()));
}








  Widget _buildNavItem(IconData icon, String label, bool isActive, VoidCallback onTap) {
    final isDarkMode = Theme.of(context).brightness == Brightness.dark;
    final activeColor = isDarkMode ? Colors.blueAccent : const Color(0xFF1E99D3);
    
    return GestureDetector(
      onTap: onTap,
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            icon,
            color: isActive ? activeColor : isDarkMode ? Colors.white70 : Colors.grey[600],
            size: 26,
          ),
          const SizedBox(height: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 10,
              color: isActive ? activeColor : isDarkMode ? Colors.white70 : Colors.grey[600],
            ),
          ),
        ],
      ),
    );
  }

  void _showSettingsPanel() {
    bool isDarkMode = Theme.of(context).brightness == Brightness.dark;
    
    showModalBottomSheet(
      context: context,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(30)),
      ),
      backgroundColor: Theme.of(context).scaffoldBackgroundColor,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setModalState) {
            return Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Container(
                    width: 50,
                    height: 5,
                    decoration: BoxDecoration(
                      color: Colors.grey[400],
                      borderRadius: BorderRadius.circular(10),
                    ),
                  ),
                  const SizedBox(height: 20),
                  Text(
                    "Configuraciones",
                    style: TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      color: isDarkMode ? Colors.white : Colors.black87,
                    ),
                  ),
                  const SizedBox(height: 25),
                  SwitchListTile(
                    title: Text(
                      "Modo Oscuro",
                      style: TextStyle(
                        color: isDarkMode ? Colors.white : Colors.black87,
                      ),
                    ),
                    secondary: Icon(
                      Icons.dark_mode,
                      color: isDarkMode ? Colors.amber : Colors.grey,
                    ),
                    value: isDarkMode,
                    onChanged: (value) {
                      setModalState(() {
                        isDarkMode = value;
                      });
                      widget.onToggleTheme?.call();
                    },
                  ),
                  ListTile(
                    leading: const Icon(Icons.support_agent, color: Colors.purple),
                    title: Text(
                      "Soporte / Contacto",
                      style: TextStyle(
                        color: isDarkMode ? Colors.white : Colors.black87,
                      ),
                    ),
                    onTap: () {
                      launchUrlString("https://wa.me/573118952249");
                    },
                  ),
                  const SizedBox(height: 20),
                ],
              ),
            );
          },
        );
      },
    );
  }

  void _showSocialMediaBottomSheet() {
    final isDarkMode = Theme.of(context).brightness == Brightness.dark;
    
    showModalBottomSheet(
      context: context,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(30)),
      ),
      backgroundColor: Theme.of(context).scaffoldBackgroundColor,
      builder: (context) {
        return Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 50,
                height: 5,
                decoration: BoxDecoration(
                  color: Colors.grey[400],
                  borderRadius: BorderRadius.circular(10),
                ),
              ),
              const SizedBox(height: 20),
              Text(
                "Síguenos en",
                style: TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                  color: isDarkMode ? Colors.white : Colors.black87,
                ),
              ),
              const SizedBox(height: 25),
              _buildSocialMediaItem(
                context,
                Icons.language,
                "Página Web",
                Colors.blue,
                'https://cercetasolucionesempresariales.com',
              ),
              _buildSocialMediaItem(
                context,
                Icons.facebook,
                "Facebook",
                const Color(0xFF1877F2),
                'https://facebook.com/tuempresa',
              ),
              _buildSocialMediaItem(
                context,
                Icons.camera_alt,
                "Instagram",
                const Color(0xFFE1306C),
                'https://instagram.com/tuempresa',
              ),
              _buildSocialMediaItem(
                context,
                Icons.music_note,
                "TikTok",
                Colors.black,
                'https://www.tiktok.com/@cerceta.solucion?_t=ZS-8v2GfV6wzLE&_r=1',
              ),
              const SizedBox(height: 20),
            ],
          ),
        );
      },
    );
  }

  Widget _buildSocialMediaItem(
    BuildContext context,
    IconData icon,
    String label,
    Color color,
    String url,
  ) {
    final isDarkMode = Theme.of(context).brightness == Brightness.dark;
    
    return ListTile(
      leading: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: color.withOpacity(0.2),
          shape: BoxShape.circle,
        ),
        child: Icon(icon, color: color),
      ),
      title: Text(
        label,
        style: TextStyle(
          color: isDarkMode ? Colors.white : Colors.black87,
        ),
      ),
      trailing: Icon(
        Icons.arrow_forward_ios,
        size: 16,
        color: isDarkMode ? Colors.white70 : Colors.grey,
      ),
      onTap: () => launchUrlString(url, mode: LaunchMode.externalApplication),
    );
  }
}