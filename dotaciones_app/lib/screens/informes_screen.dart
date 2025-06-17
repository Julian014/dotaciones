import 'package:flutter/material.dart';

class InformesScreen extends StatelessWidget {
  final String userId;

  const InformesScreen({Key? key, required this.userId}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Informes')),
      body: const Center(
        child: Text('Aquí van los informes del usuario.'),
      ),
    );
  }
}
