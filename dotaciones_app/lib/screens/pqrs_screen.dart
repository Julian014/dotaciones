import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:flutter_animate/flutter_animate.dart';

class PqrsScreen extends StatefulWidget {
  final String userId;

  const PqrsScreen({Key? key, required this.userId}) : super(key: key);

  @override
  State<PqrsScreen> createState() => _PqrsScreenState();
}

class _PqrsScreenState extends State<PqrsScreen> {
  final _formKey = GlobalKey<FormState>();
  String? _tipoSeleccionado;
  String _descripcion = '';
  bool _enviando = false;

  final List<String> _tipos = ['Petición', 'Queja', 'Reclamo', 'Sugerencia'];

  Future<void> enviarPQRS() async {
    if (!_formKey.currentState!.validate()) return;

    _formKey.currentState!.save();
    setState(() => _enviando = true);

    try {
      final response = await http.post(
        Uri.parse('https://sistemacerceta.com/enviar_pqrs'),
        headers: {'Content-Type': 'application/json'},
        body: '''
          {
            "userId": "${widget.userId}",
            "tipo": "${_tipoSeleccionado ?? ''}",
            "descripcion": "${_descripcion.replaceAll('"', '\\"')}"
          }
        ''',
      );

      if (response.statusCode == 200) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('✅ PQRS enviada con éxito')),
        );
        _formKey.currentState?.reset();
        setState(() => _tipoSeleccionado = null);
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('❌ Error al enviar PQRS')),
        );
      }
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('⚠️ Error de conexión')),
      );
    } finally {
      setState(() => _enviando = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      backgroundColor: isDark ? const Color(0xFF1C1C1E) : const Color(0xFFF1F3F6),
      appBar: AppBar(
        backgroundColor: isDark ? const Color(0xFF292B2F) : Colors.white,
        title: const Text(
          'PQRS',
          style: TextStyle(fontWeight: FontWeight.bold),
        ),
        elevation: 1,
        centerTitle: true,
        foregroundColor: isDark ? Colors.white : Colors.black,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Animate(
          effects: [FadeEffect(duration: 500.ms), SlideEffect(begin: Offset(0, 0.2))],
          child: Card(
            elevation: 8,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(24)),
            color: isDark ? const Color(0xFF2B2B2E) : Colors.white,
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      "Enviar PQRS",
                      style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      "Cuéntanos si tienes una queja, reclamo o sugerencia.",
                      style: TextStyle(
                        fontSize: 14,
                        color: isDark ? Colors.white60 : Colors.grey[600],
                      ),
                    ),
                    const SizedBox(height: 30),
                    DropdownButtonFormField<String>(
                      decoration: InputDecoration(
                        labelText: 'Tipo de solicitud',
                        filled: true,
                        fillColor: isDark ? Colors.black12 : Colors.grey.shade100,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(16),
                        ),
                      ),
                      value: _tipoSeleccionado,
                      items: _tipos.map((tipo) {
                        return DropdownMenuItem(value: tipo, child: Text(tipo));
                      }).toList(),
                      onChanged: (value) {
                        setState(() => _tipoSeleccionado = value);
                      },
                      validator: (value) =>
                          value == null ? 'Por favor selecciona un tipo' : null,
                    ),
                    const SizedBox(height: 24),
                    TextFormField(
                      decoration: InputDecoration(
                        labelText: 'Describe tu solicitud',
                        filled: true,
                        fillColor: isDark ? Colors.black12 : Colors.grey.shade100,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(16),
                        ),
                        alignLabelWithHint: true,
                      ),
                      maxLines: 6,
                      onSaved: (value) => _descripcion = value ?? '',
                      validator: (value) =>
                          value == null || value.isEmpty
                              ? 'Por favor escribe una descripción'
                              : null,
                    ),
                    const SizedBox(height: 30),
                    SizedBox(
                      width: double.infinity,
                      child:
                      
                      
               ElevatedButton.icon(
  onPressed: _enviando ? null : enviarPQRS,
  icon: const Icon(Icons.send_rounded),
  label: Text(
    _enviando ? 'Enviando...' : 'Enviar solicitud',
    style: const TextStyle(
      fontSize: 16,
      color: Colors.black,            // Color negro
      fontWeight: FontWeight.bold,    // Negrilla
    ),
  ),
  style: ElevatedButton.styleFrom(
    backgroundColor: Colors.purple,
    padding: const EdgeInsets.symmetric(vertical: 16),
    shape: RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(16),
    ),
    elevation: 4,
    shadowColor: Colors.black45,
  ),
),

                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
