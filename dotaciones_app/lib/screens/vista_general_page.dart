// vista_general_page.dart
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:url_launcher/url_launcher_string.dart';
import '../widgets/bottom_nav.dart';
import 'pagos.dart';
import 'informes_screen.dart';
import 'pqrs_screen.dart';
import 'domicilios.dart';

class VistaGeneralPage extends StatelessWidget {
  final String userId;

  const VistaGeneralPage({super.key, required this.userId});

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      backgroundColor: isDark ? const Color(0xFF1D1D1F) : const Color(0xFFF4F4F7),
      appBar: AppBar(
        title: const Text('Acciones disponibles'),
        backgroundColor: Colors.purple,
        elevation: 0,
      ),
      body: GridView.count(
        crossAxisCount: 2,
        padding: const EdgeInsets.all(20),
        crossAxisSpacing: 20,
        mainAxisSpacing: 20,
        children: [
          _buildActionCard(
            context,
            title: 'Pagos',
            icon: Icons.payment,
            color: Colors.deepPurple,
            onTap: () {
              Navigator.push(
                context,
MaterialPageRoute(builder: (context) => NuevoPagoScreen(userId: userId)),
              );
            },
          ),
          _buildActionCard(
            context,
            title: 'Informes',
            icon: Icons.insert_chart_outlined,
            color: Colors.indigo,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => InformesScreen(userId: userId)),
              );
            },
          ),
          _buildActionCard(
            context,
            title: 'PQRS',
            icon: Icons.support_agent,
            color: Colors.orange,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => PqrsScreen(userId: userId)),
              );
            },
          ),
_buildActionCard(
  context,
  title: 'Domicilios',
  icon: Icons.shopping_bag,
  color: Colors.teal,
  onTap: () {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => PedidosScreen(userId: userId),
      ),
    );
  },
),
          _buildActionCard(
            context,
            title: 'Blog',
            icon: Icons.newspaper,
            color: Colors.pinkAccent,
            onTap: () async {
              const blogUrl = 'https://tublog.com';
              if (await canLaunchUrlString(blogUrl)) {
                await launchUrlString(blogUrl);
              } else {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text("No se pudo abrir el blog.")),
                );
              }
            },
          ),
        ],
      ).animate().fade(duration: 400.ms).slideY(begin: 0.1),
      bottomNavigationBar: CustomBottomNav(
        onLogout: () {
          Navigator.pop(context);
        },
        onSettings: () {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text("Abrir ajustes")),
          );
        },
        onCentralButtonTap: () {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text("Ya estás en Acciones")),
          );
        },
      ),
    );
  }

  Widget _buildActionCard(
    BuildContext context, {
    required String title,
    required IconData icon,
    required Color color,
    required VoidCallback onTap,
  }) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return GestureDetector(
      onTap: onTap,
      child: Card(
        elevation: 10,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
        color: isDark ? const Color(0xFF2C2C2E) : Colors.white,
        shadowColor: Colors.black26,
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.15),
                  shape: BoxShape.circle,
                ),
                child: Icon(icon, size: 36, color: color),
              ),
              const SizedBox(height: 16),
              Text(
                title,
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                  color: isDark ? Colors.white70 : Colors.black87,
                ),
                textAlign: TextAlign.center,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
