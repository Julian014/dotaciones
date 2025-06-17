import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher_string.dart';

class CustomBottomNav extends StatelessWidget {
  final VoidCallback onLogout;
  final VoidCallback onSettings;
  final VoidCallback onCentralButtonTap;

  const CustomBottomNav({
    Key? key,
    required this.onLogout,
    required this.onSettings,
    required this.onCentralButtonTap,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Stack(
      alignment: Alignment.bottomCenter,
      children: [
        Container(
          height: 80,
          margin: const EdgeInsets.only(top: 30),
          padding: const EdgeInsets.symmetric(horizontal: 24),
          decoration: const BoxDecoration(
            color: Color(0xFFF7F5FD),
            borderRadius: BorderRadius.only(
              topLeft: Radius.circular(30),
              topRight: Radius.circular(30),
            ),
            boxShadow: [
              BoxShadow(
                color: Colors.black12,
                blurRadius: 20,
                offset: Offset(0, -6),
              ),
            ],
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              IconButton(
                icon: const Icon(Icons.home_rounded),
                iconSize: 28,
                color: Colors.purple,
                onPressed: () {
                  Navigator.pop(context); // Vuelve al Home si está en otra página
                },
              ),
              IconButton(
                icon: const Icon(Icons.public),
                iconSize: 28,
                color: Colors.purple,
                onPressed: () {
                  showModalBottomSheet(
                    context: context,
                    shape: const RoundedRectangleBorder(
                      borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
                    ),
                    backgroundColor: Colors.white,
                    builder: (context) {
                      return Padding(
                        padding: const EdgeInsets.symmetric(vertical: 20, horizontal: 16),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            const Text(
                              'Síguenos en:',
                              style: TextStyle(
                                fontSize: 18,
                                fontWeight: FontWeight.bold,
                                color: Colors.purple,
                              ),
                            ),
                            const SizedBox(height: 12),
                            ListTile(
                              leading: const Icon(Icons.language, color: Colors.purple),
                              title: const Text('Página Web'),
                              onTap: () {
                                launchUrlString('https://cercetasolucionesempresariales.com');
                              },
                            ),
                            ListTile(
                              leading: const Icon(Icons.facebook, color: Colors.blue),
                              title: const Text('Facebook'),
                              onTap: () {
                                launchUrlString('https://facebook.com/tuempresa');
                              },
                            ),
                            ListTile(
                              leading: const Icon(Icons.camera_alt, color: Colors.pink),
                              title: const Text('Instagram'),
                              onTap: () {
                                launchUrlString('https://instagram.com/tuempresa');
                              },
                            ),
                            ListTile(
                              leading: const Icon(Icons.music_note, color: Colors.black),
                              title: const Text('TikTok'),
                              onTap: () {
                                launchUrlString('https://www.tiktok.com/@cerceta.solucion?_t=ZS-8v2GfV6wzLE&_r=1');
                              },
                            ),
                          ],
                        ),
                      );
                    },
                  );
                },
              ),
              const SizedBox(width: 60),
              IconButton(
                icon: const Icon(Icons.settings),
                iconSize: 28,
                color: Colors.purple,
                onPressed: onSettings,
              ),
              IconButton(
                icon: const Icon(Icons.logout),
                iconSize: 28,
                color: Colors.purple,
                onPressed: onLogout,
              ),
            ],
          ),
        ),
        Positioned(
          bottom: 35,
          child: GestureDetector(
            onTap: onCentralButtonTap,
            child: Container(
              height: 60,
              width: 60,
              decoration: BoxDecoration(
                color: Colors.purple,
                borderRadius: BorderRadius.circular(20),
                boxShadow: const [
                  BoxShadow(
                    color: Colors.black38,
                    blurRadius: 10,
                    offset: Offset(0, 4),
                  ),
                ],
              ),
              child: const Icon(Icons.list, color: Colors.white, size: 30),
            ),
          ),
        ),
      ],
    );
  }
}
