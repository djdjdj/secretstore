root:
  user.present:
    - password: {{ salt['pillar.get']('root_hash:password') }}
    - groups:
      - root
      - bin
      - daemon
      - sys
      - adm
      - disk
      - wheel
