/**
 * Puerto del repositorio de usuarios.
 * Define las operaciones que debe implementar
 * cualquier adaptador de persistencia.
 */
class UserRepository {
  async findByEmail(email) {
    throw new Error('findByEmail() no está implementado');
  }

  async create(user) {
    throw new Error('create() no está implementado');
  }

  async findById(id) {
    throw new Error('findById() no está implementado');
  }
}

module.exports = UserRepository;